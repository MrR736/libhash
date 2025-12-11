#include <stdio.h>
#include <string.h>
#include "md5.h"

static void print_hash(MD5_HASH* digest) {
    for (int i = 0; i < MD5_HASH_SIZE; ++i) { printf("%02x", digest->bytes[i]); }
    printf("\n");
}

static int hash_matches(const MD5_HASH* digest, const char* expectedHex) {
    char hashHex[129] = {0};
    for (int i = 0; i < MD5_HASH_SIZE; ++i) sprintf(hashHex + i * 2, "%02x", digest->bytes[i]);
    return strcasecmp(hashHex, expectedHex) == 0;
}

int main() {
    struct {
        const char* message;
        const char* expected;  // Expected hex digest
    } tests[] = {
        { "", "d41d8cd98f00b204e9800998ecf8427e" },
        { "abc", "900150983cd24fb0d6963f7d28e17f72" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "8215ef0796a20bcaaae116d3876c664a" },
        { "The quick brown fox jumps over the lazy dog", "9e107d9d372bb6826bd81d3542a419d6" },
        { "The quick brown fox jumps over the lazy cog", "1055d3e698d289f2af8663725127bd4b" },
    };
    MD5_HASH digest;
    int all_passed = 1;
    for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); ++i) {
        Md5Calculate(tests[i].message, (uint32_t)strlen(tests[i].message), &digest);
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
