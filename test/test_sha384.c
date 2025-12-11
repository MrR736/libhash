#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>   // for strcasecmp
#include "sha384.h"    // must declare: Sha384Calculate(), SHA384_HASH_SIZE, SHA384_HASH

static void print_hash(const SHA384_HASH* digest) {
    for (int i = 0; i < SHA384_HASH_SIZE; ++i)
        printf("%02x", digest->bytes[i]);
    printf("\n");
}

static int hash_matches(const SHA384_HASH* digest, const char* expectedHex) {
    char hashHex[SHA384_HASH_SIZE * 2 + 1] = {0};
    for (int i = 0; i < SHA384_HASH_SIZE; ++i)
        sprintf(hashHex + i * 2, "%02x", digest->bytes[i]);
    return strcasecmp(hashHex, expectedHex) == 0;
}

int main(void) {
    struct {
        const char* message;
        const char* expected;
    } tests[] = {
        {
            "",
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
            "274edebfe76f65fbd51ad2f14898b95b"
        },
        {
            "abc",
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
            "8086072ba1e7cc2358baeca134c825a7"
        },
        {
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
            "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712"
            "fcc7c71a557e2db966c3e9fa91746039"
        },
        {
            "The quick brown fox jumps over the lazy dog",
            "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a50"
            "9cb1e5dc1e85a941bbee3d7f2afbc9b1"
        },
        {
            "The quick brown fox jumps over the lazy cog",
            "098cea620b0978caa5f0befba6ddcf22764bea977e1c70b3483edfdf1de25f4b"
            "40d6cea3cadf00f809d422feb1f0161b"
        },
    };

    SHA384_HASH digest;
    int all_passed = 1;

    for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); ++i) {
	char *m = strdup(tests[i].message);
	Sha384Calculate(m, (uint32_t)strlen(m), &digest);
	free(m);

        if (hash_matches(&digest, tests[i].expected)) {
            printf("Test %zu PASSED\n", i);
        } else {
            printf("Test %zu FAILED\n", i);
            printf("Expected: %s\n", tests[i].expected);
            printf("Got      : ");
            print_hash(&digest);
            all_passed = 0;
        }
    }

    return all_passed ? 0 : 1;
}
