#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "aes.h"  // or wherever your AES implementation lives

static uint8_t key[AES_KEY_SIZE_128] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

static uint8_t plaintext[AES_KEY_SIZE_128] = {
    0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
    0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
};

static uint8_t ciphertext[AES_KEY_SIZE_128];
static uint8_t decrypted[AES_KEY_SIZE_128];

int main(void) {
    AesContext ctx;
    int i;

    // 1. Init context
    if (AesInitialise(&ctx, key, AES_KEY_SIZE_128) != 0) {
        fprintf(stderr, "AES initialization failed\n");
        return 1;
    }

    // 2. Encrypt
    AesEncrypt(&ctx, plaintext, ciphertext);

    // 3. Decrypt
    AesDecrypt(&ctx, ciphertext, decrypted);

    // 4. Compare
    if (memcmp(&plaintext, &decrypted, AES_KEY_SIZE_128) != 0) {
        fprintf(stderr, "AES decrypt failed: mismatch : %d\n", memcmp(&plaintext, &decrypted, AES_KEY_SIZE_128));
        printf("Original : ");
        for (i = 0; i<AES_KEY_SIZE_128; i++) printf("%02X ", plaintext[i]);
        printf("\nDecrypted: ");
        for (i = 0; i<AES_KEY_SIZE_128; i++) printf("%02X ", decrypted[i]);
        printf("\n");
        return 2;
    }

    printf("AES test passed\n");
    return 0;
}
