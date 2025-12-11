#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>    // for strcasecmp (POSIX)
#include "sha224.h"     // Ensure your implementation header is correct

static void print_hash(const SHA224_HASH* digest) {
    for (int i = 0; i < SHA224_HASH_SIZE; ++i)
        printf("%02x", digest->bytes[i]);
    printf("\n");
}

static int hash_matches(const SHA224_HASH* digest, const char* expectedHex) {
    char hashHex[(SHA224_HASH_SIZE * 2) + 1];
    for (int i = 0; i < SHA224_HASH_SIZE; ++i)
        sprintf(hashHex + i * 2, "%02x", digest->bytes[i]);
    hashHex[SHA224_HASH_SIZE * 2] = '\0';
    return strcasecmp(hashHex, expectedHex) == 0;
}

int main(void) {
    struct {
        const char* message;
        const char* expected;
    } tests[] = {
        {
            "",
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        },
        {
            "abc",
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        },
        {
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
        },
        {
            "The quick brown fox jumps over the lazy dog",
            "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525"
        },
        {
            "The quick brown fox jumps over the lazy cog",
            "fee755f44a55f20fb3362cdc3c493615b3cb574ed95ce610ee5b1e9b"
        },
    };

    SHA224_HASH digest;
    int all_passed = 1;

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
        Sha224Calculate(tests[i].message, (uint32_t)strlen(tests[i].message), &digest);
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
