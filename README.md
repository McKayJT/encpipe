Encpipe
=======

The dum^H^H^Hsimplest encryption tool in the world, libsodium edition.

# Usage

Encrypt a file using a password:

```sh
encpipe -e -p password -i inputfile -o outputfile
```

Decrypt a file using a password:

```sh
encpipe -d -p password -i inputfile -o outputfile
```

`-i` and `-o` can be set to `-` or omitted to read/write from the
standard input/output.

`-P password_file` can be used to read the password, or an arbitrary
long key (that doesn't have to be text) from a file.

If you don't feel inspired, `-G` prints a random password.

Example - encrypted file transfer:

```sh
nc -l 6666 | encpipe -d -p password
encpipe -e -p password -i /etc/passwd | nc 127.0.0.1 6666
```

Example - compressed, encrypted archives:

```sh
zstd -5 -v -c "$FILE" | encpipe -e -p "$PASSWD" -o "${FILE}.zst.encpipe"
```

# Dependencies

[libsodium](https://https://github.com/jedisct1/libsodium).

# Installation

```sh
make
sudo make install
```

# Why

I wanted a simple program for streaming file encryption, but didn't
want to place my trust in the Gimli permutation yet.
