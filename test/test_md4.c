#include <stdio.h>
#include <string.h>
#include "md4.h"

static void print_hash(MD4_HASH* digest) {
    for (int i = 0; i < MD4_HASH_SIZE; ++i) { printf("%02x", digest->bytes[i]); }
    printf("\n");
}

static int hash_matches(const MD4_HASH* digest, const char* expectedHex) {
    char hashHex[129] = {0};
    for (int i = 0; i < MD4_HASH_SIZE; ++i) sprintf(hashHex + i * 2, "%02x", digest->bytes[i]);
    return strcasecmp(hashHex, expectedHex) == 0;
}

int main() {
    struct {
        const char* message;
        const char* expected;  // Expected hex digest
    } tests[] = {
        { "", "31d6cfe0d16ae931b73c59d7e0c089c0" },
        { "abc", "a448017aaf21d8525fc10ae87aa6729d" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "4691a9ec81b1a6bd1ab8557240b245c5" },
        { "The quick brown fox jumps over the lazy dog", "1bee69a46ba811185c194762abaeae90" },
        { "The quick brown fox jumps over the lazy cog", "b86e130ce7028da59e672d56ad0113df" },
    };
    MD4_HASH digest;
    int all_passed = 1;
    for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); ++i) {
        Md4Calculate(tests[i].message, (uint32_t)strlen(tests[i].message), &digest);
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
