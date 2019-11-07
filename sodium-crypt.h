#pragma once

#ifndef SODIUM_CRYPT_H
#define SODIUM_CRYPT_H

int stream_encrypt(FILE* in, FILE* out, const char* password);

int stream_decrypt(FILE* in, FILE* out, const char* password);

#endif
