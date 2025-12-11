#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sha1.h"  // Ensure this matches your actual header

static void print_hash(SHA1_HASH* digest) {
    for (int i = 0; i < SHA1_HASH_SIZE; ++i) {
        printf("%02x", digest->bytes[i]);
    }
    printf("\n");
}

// Utility: Compare a calculated SHA1 with a hex-encoded string
static int hash_matches(const SHA1_HASH* digest, const char* expectedHex) {
    char hashHex[129] = {0};
    for (int i = 0; i < SHA1_HASH_SIZE; ++i)
        sprintf(hashHex + i * 2, "%02x", digest->bytes[i]);
    return strcasecmp(hashHex, expectedHex) == 0;
}

int main(void) {
    struct {
        const char* message;
        const char* expected;  // Expected hex digest
    } tests[] = {
        { "", "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
        { "abc", "a9993e364706816aba3e25717850c26c9cd0d89d" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983e441c3bd26ebaae4aa1f95129e5e54670f1" },
        { "The quick brown fox jumps over the lazy dog", "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12" },
        { "The quick brown fox jumps over the lazy cog", "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3" },
    };

    SHA1_HASH digest;
    int all_passed = 1;
    for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); ++i) {
        Sha1Calculate(tests[i].message, (uint32_t)strlen(tests[i].message), &digest);
        if (hash_matches(&digest, tests[i].expected)) {
            printf("Test %zu PASSED\n", i);
        } else {
            printf("Test %zu FAILED\n", i);
            printf("Expected: %s\n", tests[i].expected);
            printf("Got     : ");
            print_hash(&digest);
            all_passed = 0;
        }
    }
    return all_passed ? 0 : 1;
}
