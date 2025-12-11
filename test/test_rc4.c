#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "rc4.h"  // Update this to your actual RC4 header file

int main(void) {
    const uint8_t key[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    const uint32_t keyLen = sizeof(key);
    const uint32_t dropN = 768;  // Recommended drop size to avoid weak early output

    const char* plaintext = "RC4 test vector for encryption and decryption.";
    const uint32_t length = strlen(plaintext);

    printf("Plain Text: %s\n", plaintext);

    uint8_t* encrypted = malloc(length);
    uint8_t* decrypted = malloc(length);

    if (!encrypted || !decrypted) {
        fprintf(stderr, "Memory allocation failed.\n");
        return 1;
    }

    // Encrypt
    Rc4XorWithKey(key, keyLen, dropN, plaintext, encrypted, length);

    // Decrypt
    Rc4XorWithKey(key, keyLen, dropN, encrypted, decrypted, length);

    // Check result
    if (memcmp(plaintext, decrypted, length) != 0) {
        printf("Decryption failed!\n");
        printf("Original : %s\n", plaintext);
        printf("Decrypted: %.*s\n", length, decrypted);
        free(encrypted);
        free(decrypted);
        return 2;
    }

    printf("RC4 test passed.\nEncrypted %d (hex): ", length);
    for (uint32_t i = 0; i < length; ++i) {
        printf("%02X ", encrypted[i]);
    }
    printf("\nDecrypted: %s\n", decrypted);

    free(encrypted);
    free(decrypted);
    return 0;
}
