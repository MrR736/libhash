#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <crc32_ext.h>

/* === Helper: Convert uint32_t to hex string === */
static void uint32_to_hex(uint32_t value, char *out)
{
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 8; ++i) {
        out[7 - i] = hex[value & 0xF];
        value >>= 4;
    }
    out[8] = '\0';
}

/* === Helper: Print a CRC value === */
static void print_hash(const uint32_t *digest)
{
    char hex[9];
    uint32_to_hex(*digest, hex);
    printf("%s\n", hex);
}

/* === Helper: Compare computed CRC against expected hex string === */
static int hash_matches(const uint32_t *digest, const char *expected)
{
    char hex[9];
    uint32_to_hex(*digest, hex);
    return (strcasecmp(hex, expected) == 0);
}

/* === Main test program === */
int main(void)
{
    struct {
        const char *message;
        const char *expected;  /* Expected CRC32 (IEEE) in lowercase hex */
    } tests[] = {
        { "",                     "00000000" },
        { "abc",                  "352441c2" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "171a3f5f" },
        { "The quick brown fox jumps over the lazy dog", "414fa339" },
        { "The quick brown fox jumps over the lazy cog", "4400b5bc" },
    };

    uint32_t digest;
    int all_passed = 1;

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
        digest = crc32(tests[i].message, strlen(tests[i].message));

        if (hash_matches(&digest, tests[i].expected)) {
            printf("Test %zu PASSED\n", i);
        } else {
            printf("Test %zu FAILED\n", i);
            printf("Message : \"%s\"\n", tests[i].message);
            printf("Expected: %s\n", tests[i].expected);
            printf("Got     : ");
            print_hash(&digest);
            all_passed = 0;
        }
    }

    return all_passed ? 0 : 1;
}
