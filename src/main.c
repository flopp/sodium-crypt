#include <stdio.h>
#include <string.h>

#include "sodium-crypt.h"

FILE* openFile(const char* fileName, const char* mode, FILE* stream);

FILE* openFile(const char* fileName, const char* mode, FILE* stream) {
    if (strcmp(fileName, "-") == 0) {
        return stream;
    }
    return fopen(fileName, mode);
}

int main(int argc, char** argv) {
    if ((argc != 5) || ((strcmp(argv[1], "--encrypt") != 0) &&
                        (strcmp(argv[1], "--decrypt") != 0))) {
        fprintf(stderr, "ERROR: bad command line\n");
        fprintf(stderr,
                "USAGE: %s --encrypt|--decrypt PASSWORD FILEIN FILEOUT\n",
                argv[0]);
        return 1;
    }

    const int encrypt = (strcmp(argv[1], "--encrypt") == 0);
    const char* password = argv[2];
    const char* fileNameIn = argv[3];
    const char* fileNameOut = argv[4];

    FILE* fileIn = openFile(fileNameIn, "rb", stdin);
    if (!fileIn) {
        fprintf(stderr, "ERROR: cannot open input file\n");
    }

    FILE* fileOut = openFile(fileNameOut, "wb", stdout);
    if (!fileOut) {
        fprintf(stderr, "ERROR: cannot open output file\n");
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
