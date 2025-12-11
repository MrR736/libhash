#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "aesofb.h" // Ensure this path is correct

static void printHex(const char* label, uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) { printf("%02x ", data[i]); }
    printf("\n");
}

// Test AES OFB with key and IV
int main(void) {
    const uint8_t key[AES_BLOCK_SIZE] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };

    const uint8_t iv[AES_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    };

    const char* message = "AES OFB stream cipher test message. This should round-trip properly.";
    const size_t len = strlen(message);

    uint8_t* ciphertext = malloc(len);
    uint8_t* decrypted = malloc(len);
    if (!ciphertext || !decrypted) {
        fprintf(stderr, "Memory allocation failed.\n");
        return 1;
    }

    // Encrypt
    if (AesOfbXorWithKey(key, sizeof(key), iv, message, ciphertext, len) != 0) {
        fprintf(stderr, "Encryption failed.\n");
        free(ciphertext);
        free(decrypted);
        return 2;
    }

    // Decrypt (OFB decrypt = encrypt with same key/IV)
    if (AesOfbXorWithKey(key, sizeof(key), iv, ciphertext, decrypted, len) != 0) {
        fprintf(stderr, "Decryption failed.\n");
        free(ciphertext);
        free(decrypted);
        return 3;
    }


    // Verify result
    if (memcmp(message, decrypted, len) != 0) {
        fprintf(stderr, "Decryption mismatch!\n");
        printf("Original:  %.*s\n", (int)len, message);
        printf("Decrypted: %.*s\n", (int)len, decrypted);
        free(ciphertext);
        free(decrypted);
        return 4;
    }

    printf("OFB AES test passed.\n");
    printHex("Encrypted Data", ciphertext, len);
    printf("Decrypted message: %s\n", decrypted);
    free(ciphertext);
    free(decrypted);
    return 0;
}
