#include "encpipe_p.h"

static struct option getopt_long_options[] = {
    { "help", 0, NULL, 'h' },     { "decrypt", 0, NULL, 'd' }, { "encrypt", 0, NULL, 'e' },
    { "in", 1, NULL, 'i' },       { "out", 1, NULL, 'o' },     { "pass", 1, NULL, 'p' },
    { "passfile", 1, NULL, 'P' }, { "passgen", 0, NULL, 'G' }, { NULL, 0, NULL, 0 }
};
static const char *getopt_options = "hdeGi:o:p:P:";

static void
usage(void)
{
    puts(
        "Usage:\n\n"
        "Encrypt: encpipe -e -p <password>      [-i <inputfile>] [-o <outputfile>]\n"
        "         encpipe -e -P <password file> [-i <inputfile>] [-o <outputfile>]\n\n"
        "Decrypt: encpipe -d -p <password>      [-i <inputfile>] [-o <outputfile>]\n"
        "         encpipe -d -P <password file> [-i <inputfile>] [-o <outputfile>]\n\n"
        "Passgen: encpipe -G\n");
    exit(0);
}

static int
file_open(const char *file, int create)
{
    int fd;

    if (file == NULL || (file[0] == '-' && file[1] == 0)) {
        return create ? STDOUT_FILENO : STDIN_FILENO;
    }
    fd = create ? open(file, O_CREAT | O_WRONLY | O_TRUNC, 0644) : open(file, O_RDONLY);
    if (fd == -1) {
        die(1, "Unable to access [%s]", file);
    }
    return fd;
}

static void
derive_key(Context *ctx, char *password, size_t password_len)
{
    uint8_t salt[crypto_pwhash_SALTBYTES];

    assert(crypto_pwhash_SALTBYTES >= crypto_generichash_BYTES_MIN);

    if (ctx->has_key) {
        die(0, "A single key is enough");
    }

    crypto_generichash(salt, sizeof salt, (unsigned char *)password, password_len, NULL, 0);

    if (crypto_pwhash(ctx->key, sizeof ctx->key, password, password_len, salt,
                crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                crypto_pwhash_ALG_ARGON2ID13) != 0) {
        die(0, "Password hashing failed");
    }

    sodium_memzero(password, password_len);
    ctx->has_key = 1;
}

static int
stream_encrypt(Context *ctx)
{
    unsigned char *const chunk_size_p = ctx->buf;
    unsigned char *const chunk        = chunk_size_p + 4;
    ssize_t              max_chunk_size;
    ssize_t              chunk_size;

    assert(ctx->sizeof_buf >= crypto_secretstream_xchacha20poly1305_HEADERBYTES +
                              crypto_secretstream_xchacha20poly1305_ABYTES + 4);
    max_chunk_size = ctx->sizeof_buf - crypto_secretstream_xchacha20poly1305_ABYTES - 4;
    assert(max_chunk_size <= 0x7fffffff);

    /* push header before first chunk */
    crypto_secretstream_xchacha20poly1305_init_push(ctx->state, ctx->buf, ctx->key);
    if (safe_write(ctx->fd_out, ctx->buf,
                crypto_secretstream_xchacha20poly1305_HEADERBYTES, -1) < 0) {
        die(1, "write()");
    }
    while ((chunk_size = safe_read_partial(ctx->fd_in, ctx->rbuf, max_chunk_size)) >= 0) {
        STORE32_LE(chunk_size_p, (uint32_t) chunk_size);
        if (crypto_secretstream_xchacha20poly1305_push(ctx->state, chunk, NULL, ctx->rbuf, chunk_size,
                NULL, 0, chunk_size == 0 ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0) != 0) {
            die(0, "Encryption error");
        }
        if (safe_write(ctx->fd_out, chunk_size_p,
                4 + crypto_secretstream_xchacha20poly1305_ABYTES + chunk_size, -1) < 0) {
            die(1, "write()");
        }
        if (chunk_size == 0) {
            break;
        }
    }
    if (chunk_size < 0) {
        die(1, "read()");
    }
    return 0;
}

static int
stream_decrypt(Context *ctx)
{
    unsigned char        tag;
    ssize_t              chunk_id;
    ssize_t              readnb;
    ssize_t              max_chunk_size;
    ssize_t              chunk_size;

    assert(ctx->sizeof_buf >= crypto_secretstream_xchacha20poly1305_HEADERBYTES +
                              crypto_secretstream_xchacha20poly1305_ABYTES + 4);
    max_chunk_size = ctx->sizeof_buf - crypto_secretstream_xchacha20poly1305_ABYTES - 4;
    assert(max_chunk_size <= 0x7fffffff);

    /* pull header before first chunk */
    if (safe_read(ctx->fd_in, ctx->rbuf, crypto_secretstream_xchacha20poly1305_HEADERBYTES) !=
            crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
        die(1, "read()");
    }
    if (crypto_secretstream_xchacha20poly1305_init_pull(ctx->state, ctx->rbuf, ctx->key) != 0) {
        die(0, "Invalid header");
    }
    chunk_id = 0;
    tag = 0;
    while ((readnb = safe_read(ctx->fd_in, ctx->rbuf, 4)) == 4) {
        chunk_size = LOAD32_LE(ctx->rbuf);
        if (chunk_size > max_chunk_size) {
            die(0, "Chunk size too large ([%zd] > [%zd])", chunk_size, max_chunk_size);
        }
        if (safe_read(ctx->fd_in, ctx->rbuf, chunk_size + crypto_secretstream_xchacha20poly1305_ABYTES) !=
            chunk_size + crypto_secretstream_xchacha20poly1305_ABYTES) {
            die(0, "Chunk too short ([%zd] bytes expected)", chunk_size);
        }
        if (crypto_secretstream_xchacha20poly1305_pull(ctx->state, ctx->buf, NULL, &tag, ctx->rbuf,
                    chunk_size + crypto_secretstream_xchacha20poly1305_ABYTES, NULL, 0) != 0) {
            fprintf(stderr, "Unable to decrypt chunk #%" PRIu64 " - ", chunk_id);
            if (chunk_id == 0) {
                die(0, "Wrong password or key?");
            } else {
                die(0, "Corrupted or incomplete file?");
            }
        }
        if (safe_write(ctx->fd_out, ctx->buf, chunk_size, -1) < 0) {
            die(1, "write()");
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            break;
        }
        chunk_id++;
    }
    if (readnb < 0) {
        die(1, "read()");
    }
    if (tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
        die(0, "Premature end of file");
    }
    return 0;
}

static int
read_password_file(Context *ctx, const char *file)
{
    char    password_[512], *password = password_;
    ssize_t password_len;
    int     fd;

    fd = file_open(file, 0);
    if ((password_len = safe_read(fd, password, sizeof password_)) < 0) {
        die(1, "Unable to read the password");
    }
    while (password_len > 0 &&
           (password[password_len - 1] == ' ' || password[password_len - 1] == '\r' ||
            password[password_len - 1] == '\n')) {
        password_len--;
    }
    while (password_len > 0 && (*password == ' ' || *password == '\r' || *password == '\n')) {
        password++;
        password_len--;
    }
    if (password_len <= 0) {
        die(0, "Empty password");
    }
    close(fd);
    derive_key(ctx, password, password_len);

    return 0;
}

static void
passgen(void)
{
    unsigned char password[32];
    char          hex[32 * 2 + 1];

    randombytes_buf(password, sizeof password);
    sodium_bin2hex(hex, sizeof hex, password, sizeof password);
    puts(hex);
    sodium_memzero(password, sizeof password);
    sodium_memzero(hex, sizeof hex);
    exit(0);
}

static void
options_parse(Context *ctx, int argc, char *argv[])
{
    int opt_flag;
    int option_index = 0;

    ctx->encrypt = -1;
    ctx->in      = NULL;
    ctx->out     = NULL;
    optind       = 0;
#ifdef _OPTRESET
    optreset = 1;
#endif
    while ((opt_flag = getopt_long(argc, argv, getopt_options, getopt_long_options,
                                   &option_index)) != -1) {
        switch (opt_flag) {
        case 'd':
            ctx->encrypt = 0;
            break;
        case 'e':
            ctx->encrypt = 1;
            break;
        case 'G':
            passgen();
            break;
        case 'i':
            ctx->in = optarg;
            break;
        case 'o':
            ctx->out = optarg;
            break;
        case 'p':
            derive_key(ctx, optarg, strlen(optarg));
            break;
        case 'P':
            read_password_file(ctx, optarg);
            break;
        default:
            usage();
        }
    }
    if (ctx->has_key == 0 || ctx->encrypt == -1) {
        usage();
    }
}

int
main(int argc, char *argv[])
{
    Context ctx;

    if (sodium_init() < 0) {
        die(1, "Unable to initialize the crypto library");
    }
    memset(&ctx, 0, sizeof ctx);
    options_parse(&ctx, argc, argv);
    ctx.sizeof_buf = DEFAULT_BUFFER_SIZE;
    if (ctx.sizeof_buf < MIN_BUFFER_SIZE) {
        ctx.sizeof_buf = MIN_BUFFER_SIZE;
    } else if (ctx.sizeof_buf > MAX_BUFFER_SIZE) {
        ctx.sizeof_buf = MAX_BUFFER_SIZE;
    }
    if ((ctx.buf = (unsigned char *) malloc(ctx.sizeof_buf)) == NULL) {
        die(1, "malloc()");
    }
    if ((ctx.rbuf = (unsigned char *) malloc(ctx.sizeof_buf)) == NULL) {
        die(1, "malloc()");
    }
    if ((ctx.state = malloc(sizeof(crypto_secretstream_xchacha20poly1305_state))) == NULL) {
        die(1, "malloc()");
    }

    ctx.fd_in  = file_open(ctx.in, 0);
    ctx.fd_out = file_open(ctx.out, 1);
    if (ctx.encrypt) {
        stream_encrypt(&ctx);
    } else {
        stream_decrypt(&ctx);
    }
    free(ctx.buf);
    close(ctx.fd_out);
    close(ctx.fd_in);
    sodium_memzero(&ctx, sizeof ctx);

    return 0;
}
