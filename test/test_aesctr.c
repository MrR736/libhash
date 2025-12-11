#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "aesctr.h" // ensure correct path to header

static void printHex(const char* label, uint8_t* data, size_t len) {
    printf("%s: ", label);
    printf("i = %zu: ", len);
    for (size_t i = 0; i < len; i++) { printf("%02x ", data[i]); }
    printf("\n");
}

int main(void) {
    const uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    const uint8_t iv[AES_CTR_IV_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

    const uint8_t plaintext[] =
        "This is a test message for AES CTR mode. It doesn't need to be block-aligned.";

    size_t len = sizeof(plaintext) - 1; // exclude null terminator

    uint8_t *ciphertext = malloc(len), *decrypted = malloc(len);
    if (!ciphertext || !decrypted) {
        fprintf(stderr, "Memory allocation failed.\n");
        return 1;
    }

    // Encrypt
    if (AesCtrXorWithKey(key, sizeof(key), iv, plaintext, ciphertext, len) != 0) {
        fprintf(stderr, "CTR encryption failed.\n");
        free(ciphertext);
        free(decrypted);
        return 2;
    }

    // Decrypt
    if (AesCtrXorWithKey(key, sizeof(key), iv, ciphertext, decrypted, len) != 0) {
        fprintf(stderr, "CTR decryption failed.\n");
        free(ciphertext);
        free(decrypted);
        return 3;
    }

    // Compare
    if (memcmp(plaintext, decrypted, len) != 0) {
        fprintf(stderr, "Decryption mismatch!\n");
        printf("Original:  %.*s\n", (int)len, plaintext);
        printf("Decrypted: %.*s\n", (int)len, decrypted);
        free(ciphertext);
        free(decrypted);
        return 4;
    }

    printf("CTR AES test passed.\n");
    printHex("Encrypted Data", ciphertext, len);
    printf("Decrypted message: %s\n", decrypted);
    free(ciphertext);
    free(decrypted);
    return 0;
}
