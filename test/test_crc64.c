#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include "crc64_ext.h"

/* === Helper: Convert uint64_t to hex string === */
static void uint64_to_hex(uint64_t value, char *out)
{
	static const char hex[] = "0123456789abcdef";

	for (int i = 0; i < 16; ++i) {
		out[15 - i] = hex[value & 0xF];
		value >>= 4;
	}

	out[16] = '\0';
}

/* === Helper: Print a CRC value === */
static void print_hash(const uint64_t *digest)
{
	char hex[17];
	uint64_to_hex(*digest, hex);
	printf("%s\n", hex);
}

/* === Helper: Compare computed CRC against expected hex string === */
static int hash_matches(const uint64_t *digest, const char *expected)
{
	char hex[17];
	uint64_to_hex(*digest, hex);
	return (strcasecmp(hex, expected) == 0);
}

/* === Main test program === */
int main(void)
{
	struct {
		const char *message;
		const char *expected;  /* Expected CRC64 (IEEE) in lowercase hex */
	} tests[] = {
		{ "",					 "0000000000000000" },
		{ "abc",				  "66501A349A0E0855" },
		{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "29d18301fe33ca5d" },
		{ "The quick brown fox jumps over the lazy dog", "41e05242ffa9883b" },
		{ "The quick brown fox jumps over the lazy cog", "aa68949f5b8cc26e" },
		{ "123456789", "6C40DF5F0B497347" },
	};

	uint64_t digest;
	int all_passed = 1;

	for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
		digest = cccrc64(crc64_init_table,ccrc64,tests[i].message, strlen(tests[i].message),CRC64_ECMA_POLY,CRC64_INIT_0,CRC64_XOR_0);

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
