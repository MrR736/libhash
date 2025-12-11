#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "aescbc.h"

// Sample data for testing
static uint8_t Key[AES_BLOCK_SIZE] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x97, 0x75, 0x46, 0x8d, 0x27, 0x3c
};

static uint8_t IV[AES_BLOCK_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static uint8_t InputData[AES_KEY_SIZE_256] = "This is a test of AES CBC mode!";

// Output buffers
static uint8_t EncryptedData[AES_KEY_SIZE_256];
static uint8_t DecryptedData[AES_KEY_SIZE_256];

static void printHex(const char* label, uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) { printf("%02x ", data[i]); }
    printf("\n");
}

int main() {
    AesCbcContext cbcContext;
    int result;

    // Initialize AES CBC context with key and IV
    result = AesCbcInitialiseWithKey(&cbcContext, Key, AES_BLOCK_SIZE, IV);
    if (result != 0) {
        printf("Error initializing AES CBC\n");
        return -1;
    }

    // Encrypt data
    result = AesCbcEncrypt(&cbcContext, InputData, EncryptedData, sizeof(InputData));
    if (result != 0) {
        printf("Error encrypting data\n");
        return -1;
    }

    // Print encrypted data in hexadecimal format
    printHex("Encrypted Data", EncryptedData, sizeof(EncryptedData));

    // Reset CBC context for decryption
    result = AesCbcInitialiseWithKey(&cbcContext, Key, AES_BLOCK_SIZE, IV);
    if (result != 0) {
        printf("Error reinitializing AES CBC for decryption\n");
        return -1;
    }

    // Decrypt data
    result = AesCbcDecrypt(&cbcContext, EncryptedData, DecryptedData, sizeof(EncryptedData));
    if (result != 0) {
        printf("Error decrypting data\n");
        return -1;
    }

    // Print decrypted data
    printf("Decrypted Data: %s\n", DecryptedData);

    // Check if decrypted data matches original input
    if (memcmp(InputData, DecryptedData, sizeof(InputData)) == 0) {
        printf("AES CBC encryption and decryption test passed!\n");
    } else {
        printf("AES CBC encryption and decryption test failed!\n");
    }

    return 0;
}
