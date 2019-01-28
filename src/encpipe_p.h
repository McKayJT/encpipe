#ifndef encpipe_p_H
#define encpipe_p_H 1

#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sodium.h>

#include "common.h"
#include "safe_rw.h"

#define MIN_BUFFER_SIZE 512
#define MAX_BUFFER_SIZE 0x7fffffff
#define DEFAULT_BUFFER_SIZE (1 * 1024 * 1024)

typedef struct Context_ {
    crypto_secretstream_xchacha20poly1305_state *state;
    char *         in;
    char *         out;
    unsigned char  key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    unsigned char *buf;
    unsigned char *rbuf;
    size_t         sizeof_buf;
    int            fd_in;
    int            fd_out;
    int            encrypt;
    int            has_key;
} Context;

#endif
