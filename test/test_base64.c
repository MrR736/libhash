#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <base64.h>

// Helper function to print binary data as hex
static void print_hex(const void *data, size_t len) {
    const unsigned char *p = data;
    for (size_t i = 0; i < len; i++)
        printf("%02X", p[i]);
}

// Helper to test one encode/decode cycle
static void test_base64_variant(
    const char *variant_name,
    char *(*encode_fn)(const void *, size_t),
    int (*decode_fn)(const char *, void **, size_t *))
{
    const char *input = "Hello, world!";
    printf("---- %s ----\n", variant_name);
    printf("Input: \"%s\"\n", input);

    // Encode
    char *encoded = encode_fn(input, strlen(input));
    if (!encoded) {
        printf("Encoding failed!\n\n");
        return;
    }
    printf("Encoded: %s\n", encoded);

    // Decode
    void *decoded = NULL;
    size_t decoded_len = 0;
    int rc = decode_fn(encoded, &decoded, &decoded_len);
    if (rc != BASE64_SUCCESS) {
        printf("Decoding failed! (error %d)\n\n", rc);
        free(encoded);
        return;
    }

    printf("Decoded (hex): ");
    print_hex(decoded, decoded_len);
    printf("\nDecoded (text): \"%.*s\"\n", (int)decoded_len, (char *)decoded);

    // Cleanup
    free(encoded);
    free(decoded);
    printf("\n");
}

int main(void) {
    printf("=== Base32 Test Program ===\n\n");

    test_base64_variant("Standard Base64", base64_encode, base64_decode);
    test_base64_variant("Base64URL", base64url_encode, base64url_decode);
    test_base64_variant("Base64 MIME", base64mime_encode, base64mime_decode);

    return 0;
}
