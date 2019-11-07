#include <stdio.h>
#include <string.h>
#include <sodium.h>

#define CHUNK_SIZE 65536

void fatal(const char* message) __attribute__ ((noreturn));
void derive_key(
    const char* password,
    const unsigned char salt[crypto_pwhash_SALTBYTES],
    unsigned char key[crypto_box_SEEDBYTES]);

void stream_encrypt(
    FILE* in,
    FILE* out,
    const char* password);


void stream_decrypt(
    FILE* in,
    FILE* out,
    const char* password);
FILE* openFile(
    const char* fileName,
    const char* mode,
    FILE* stream);


void fatal(const char* message) {
    fprintf(stderr, "ERROR: %s\n", message);
    exit(1);
}

void derive_key(
    const char* password,
    const unsigned char salt[crypto_pwhash_SALTBYTES],
    unsigned char key[crypto_box_SEEDBYTES]
) {
    if (crypto_pwhash(
            key, crypto_box_SEEDBYTES,
            password, strlen(password),
            salt,
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_ARGON2ID13) != 0
    ) {
        fatal("key derivation failed");
    }
}

void stream_encrypt(
    FILE* in,
    FILE* out,
    const char* password
) {
    if (sodium_init() < 0) {
        fatal("sodium init failed");
    }

    /* generate salt */
    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof salt);

    /* derive key */
    unsigned char key[crypto_box_SEEDBYTES];
    derive_key(password, salt, key);

    /* write salt */
    if (fwrite(salt, 1, sizeof salt, out) != sizeof salt) {
        fatal("writing salt failed");
    }

    /* init cipher */
    crypto_secretstream_xchacha20poly1305_state st;
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);

    /* write header */
    if (fwrite(header, 1, sizeof header, out) != sizeof header) {
        fatal("writing header failed");
    }

    while (1) {
        /* read paintext chunk */
        unsigned char bufferIn[CHUNK_SIZE];
        const size_t readLen = fread(bufferIn, 1, sizeof bufferIn, in);
        const int eof = feof(in);
        const unsigned char tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;

        /* encrypt chunk */
        unsigned char bufferOut[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
        unsigned long long outputLen;
        crypto_secretstream_xchacha20poly1305_push(&st, bufferOut, &outputLen, bufferIn, readLen, NULL, 0, tag);

        /* write ciphertext chunk */
        if (fwrite(bufferOut, 1, (size_t)outputLen, out) != outputLen) {
            fatal("writing chunk failed");
        }

        if (eof) {
            break;
        }
    }
}

void stream_decrypt(
    FILE* in,
    FILE* out,
    const char* password
) {
    if (sodium_init() < 0) {
        fatal("sodium init failed");
    }

    /* read salt */
    unsigned char salt[crypto_pwhash_SALTBYTES];
    if (fread(salt, 1, sizeof salt, in) != sizeof salt) {
        fatal("incomplete salt");
    }

    /* derive key */
    unsigned char key[crypto_box_SEEDBYTES];
    derive_key(password, salt, key);

    /* read header */
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    if (fread(header, 1, sizeof header, in) != sizeof header) {
        fatal("incomplete header");
    }

    /* init cipher */
    crypto_secretstream_xchacha20poly1305_state st;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        fatal("invalid header");
    }

    while (1) {
        /* read ciphertext chunk */
        unsigned char bufferIn[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
        const size_t readLen = fread(bufferIn, 1, sizeof bufferIn, in);
        const int eof = feof(in);

        /* decrypt chunk */
        unsigned char bufferOut[CHUNK_SIZE];
        unsigned long long outputLen;
        unsigned char tag;
        if (crypto_secretstream_xchacha20poly1305_pull(&st, bufferOut, &outputLen, &tag, bufferIn, readLen, NULL, 0) != 0) {
            fatal("corrupt chunk");
        }
        if ((tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) && (!eof)) {
            fatal("premature end");
        }

        /* write plaintext chunk */
        if (fwrite(bufferOut, 1, (size_t) outputLen, out) != outputLen) {
            fatal("writing chunk failed");
        }

        if (eof) {
            break;
        }
    }
}

FILE* openFile(
    const char* fileName,
    const char* mode,
    FILE* stream
) {
    if (strcmp(fileName, "-") == 0) {
        return stream;
    }
    return fopen(fileName, mode);
}

int main(int argc, char** argv) {
    if ((argc != 5) || ((strcmp(argv[1], "--encrypt") != 0) && (strcmp(argv[1], "--decrypt") != 0))) {
        fprintf(stderr, "ERROR: bad command line\n");
        fprintf(stderr, "USAGE: %s --encrypt|--decrypt PASSWORD FILEIN FILEOUT\n", argv[0]);
        return 1;
    }
    
    const int   encrypt     = (strcmp(argv[1], "--encrypt") == 0);
    const char* password    = argv[2];
    const char* fileNameIn  = argv[3];
    const char* fileNameOut = argv[4];
    
    FILE* fileIn = openFile(fileNameIn, "rb", stdin);
    if (!fileIn) {
        fatal("cannot open input file");
    }

    FILE* fileOut = openFile(fileNameOut, "wb", stdout);
    if (!fileOut) {
        fatal("cannot open output file");
    }
   
    if (encrypt) {
        stream_encrypt(fileIn, fileOut, password);
    } else {
        stream_decrypt(fileIn, fileOut, password);
    }

    fclose(fileIn);
    fclose(fileOut);

    return 0;
}
