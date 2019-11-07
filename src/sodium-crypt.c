#include <sodium.h>
#include <stdio.h>
#include <string.h>

#include "sodium-crypt.h"

#define CHUNK_SIZE 65536

int derive_key(const char* password,
               const unsigned char salt[crypto_pwhash_SALTBYTES],
               unsigned char key[crypto_box_SEEDBYTES]);

int derive_key(const char* password,
               const unsigned char salt[crypto_pwhash_SALTBYTES],
               unsigned char key[crypto_box_SEEDBYTES]) {
    if (crypto_pwhash(key, crypto_box_SEEDBYTES, password, strlen(password),
                      salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        fprintf(stderr, "ERROR: key derivation failed\n");
        return 1;
    }

    return 0;
}

int stream_encrypt(FILE* in, FILE* out, const char* password) {
    if (sodium_init() < 0) {
        fprintf(stderr, "ERROR: sodium init failed\n");
        return 1;
    }

    /* generate salt */
    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof salt);

    /* derive key */
    unsigned char key[crypto_box_SEEDBYTES];
    if (derive_key(password, salt, key) != 0) {
        return 1;
    }

    /* write salt */
    if (fwrite(salt, 1, sizeof salt, out) != sizeof salt) {
        fprintf(stderr, "ERROR: writing salt failed\n");
        return 1;
    }

    /* init cipher */
    crypto_secretstream_xchacha20poly1305_state st;
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);

    /* write header */
    if (fwrite(header, 1, sizeof header, out) != sizeof header) {
        fprintf(stderr, "ERROR: writing header failed\n");
        return 1;
    }

    while (1) {
        /* read paintext chunk */
        unsigned char bufferIn[CHUNK_SIZE];
        const size_t readLen = fread(bufferIn, 1, sizeof bufferIn, in);
        const int eof = feof(in);
        const unsigned char tag =
            eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;

        /* encrypt chunk */
        unsigned char bufferOut[CHUNK_SIZE +
                                crypto_secretstream_xchacha20poly1305_ABYTES];
        unsigned long long outputLen;
        crypto_secretstream_xchacha20poly1305_push(
            &st, bufferOut, &outputLen, bufferIn, readLen, NULL, 0, tag);

        /* write ciphertext chunk */
        if (fwrite(bufferOut, 1, (size_t)outputLen, out) != outputLen) {
            fprintf(stderr, "ERROR: writing chunk failed\n");
            return 1;
        }

        if (eof) {
            break;
        }
    }

    return 0;
}

int stream_decrypt(FILE* in, FILE* out, const char* password) {
    if (sodium_init() < 0) {
        fprintf(stderr, "ERROR: sodium init failed\n");
        return 1;
    }

    /* read salt */
    unsigned char salt[crypto_pwhash_SALTBYTES];
    if (fread(salt, 1, sizeof salt, in) != sizeof salt) {
        fprintf(stderr, "ERROR: incomplete salt\n");
        return 1;
    }

    /* derive key */
    unsigned char key[crypto_box_SEEDBYTES];
    if (derive_key(password, salt, key) != 0) {
        return 1;
    }

    /* read header */
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    if (fread(header, 1, sizeof header, in) != sizeof header) {
        fprintf(stderr, "ERROR: incomplete header\n");
        return 1;
    }

    /* init cipher */
    crypto_secretstream_xchacha20poly1305_state st;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) !=
        0) {
        fprintf(stderr, "ERROR: invalid header\n");
        return 1;
    }

    while (1) {
        /* read ciphertext chunk */
        unsigned char
            bufferIn[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
        const size_t readLen = fread(bufferIn, 1, sizeof bufferIn, in);
        const int eof = feof(in);

        /* decrypt chunk */
        unsigned char bufferOut[CHUNK_SIZE];
        unsigned long long outputLen;
        unsigned char tag;
        if (crypto_secretstream_xchacha20poly1305_pull(
                &st, bufferOut, &outputLen, &tag, bufferIn, readLen, NULL, 0) !=
            0) {
            fprintf(stderr, "ERROR: corrupt chunk\n");
            return 1;
        }
        if ((tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) &&
            (!eof)) {
            fprintf(stderr, "ERROR: premature end\n");
            return 1;
        }

        /* write plaintext chunk */
        if (fwrite(bufferOut, 1, (size_t)outputLen, out) != outputLen) {
            fprintf(stderr, "ERROR: writing chunk failed\n");
            return 1;
        }

        if (eof) {
            break;
        }
    }

    return 0;
}
