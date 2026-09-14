#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include "crc8_ext.h"

/* === Helper: Convert uint8_t to hex string === */
static void uint8_to_hex(uint8_t value, char *out)
{
	static const char hex[] = "0123456789abcdef";

	out[0] = hex[(value >> 4) & 0x0F];
	out[1] = hex[value & 0x0F];
	out[2] = '\0';
}

/* === Helper: Print a CRC value === */
static void print_hash(const uint8_t *digest)
{
	char hex[5];

	uint8_to_hex(*digest, hex);
	printf("%s\n", hex);
}

/* === Helper: Compare computed CRC against expected hex string === */
static int hash_matches(const uint8_t *digest, const char *expected)
{
	char hex[5];

	uint8_to_hex(*digest, hex);

	return (strcasecmp(hex, expected) == 0);
}

/* === Main test program === */
int main(void)
{
	struct {
		const char *message;
		const char *expected;  /* Expected CRC-8/SMBUS in lowercase hex */
	} tests[] = {
		{ "", "00" },
		{ "abc", "5f" },
		{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "dc" },
		{ "The quick brown fox jumps over the lazy dog", "c1" },
		{ "The quick brown fox jumps over the lazy cog", "d7" },
		{ "123456789", "f4" },
	};

	uint8_t digest;
	int all_passed = 1;

	for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
		digest = crc8(tests[i].message, strlen(tests[i].message));

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
