#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include "crc16_ext.h"

/* === Helper: Convert uint16_t to hex string === */
static void uint16_to_hex(uint16_t value, char *out)
{
	static const char hex[] = "0123456789abcdef";

	for (int i = 0; i < 4; ++i) {
		out[3 - i] = hex[value & 0xF];
		value >>= 4;
	}

	out[4] = '\0';
}

/* === Helper: Print a CRC value === */
static void print_hash(const uint16_t *digest)
{
	char hex[5];

	uint16_to_hex(*digest, hex);
	printf("%s\n", hex);
}

/* === Helper: Compare computed CRC against expected hex string === */
static int hash_matches(const uint16_t *digest, const char *expected)
{
	char hex[5];

	uint16_to_hex(*digest, hex);

	return (strcasecmp(hex, expected) == 0);
}

/* === Main test program === */
int main(void)
{
	struct {
		const char *message;
		const char *expected;  /* Expected CRC-16/IBM (ARC) in lowercase hex */
	} tests[] = {
		{ "", "0000" },
		{ "abc", "9738" },
		{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "7d26" },
		{ "The quick brown fox jumps over the lazy dog", "fcdf" },
		{ "The quick brown fox jumps over the lazy cog", "3d6e" },
		{ "123456789", "bb3d" },
	};

	uint16_t digest;
	int all_passed = 1;

	for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
		digest = crc16(tests[i].message, strlen(tests[i].message));

		if (hash_matches(&digest, tests[i].expected)) {
			printf("Test %zu PASSED\n", i);
		} else {
			printf("Test %zu FAILED\n", i);
			all_passed = 0;
		}

		printf("Message : \"%s\"\n", tests[i].message);
		printf("Expected: %s\n", tests[i].expected);
		printf("Got     : ");
		print_hash(&digest);
	}

	return all_passed ? 0 : 1;
}
