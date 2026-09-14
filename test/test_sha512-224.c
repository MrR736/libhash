#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>

#include "sha512-224.h"

static void print_hash(const SHA512_224_HASH* digest) {
	for (int i = 0; i < SHA512_224_HASH_SIZE; ++i)
		printf("%02x", digest->bytes[i]);

	printf("\n");
}

static int hash_matches(
	const SHA512_224_HASH* digest,
	const char* expectedHex
) {
	char hashHex[SHA512_224_HASH_SIZE * 2 + 1] = {0};

	for (int i = 0; i < SHA512_224_HASH_SIZE; ++i)
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
			"6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"
		},
		{
			"abc",
			"4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"
		},
		{
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			"e5302d6d54bb242275d1e7622d68df6eb02dedd13f564c13dbda2174"
		},
		{
			"The quick brown fox jumps over the lazy dog",
			"944cd2847fb54558d4775db0485a50003111c8e5daa63fe722c6aa37"
		},
		{
			"The quick brown fox jumps over the lazy cog",
			"2b9d6565a7e40f780ba8ab7c8dcf41e3ed3b77997f4c55aa987eede5"
		},
	};

	SHA512_224_HASH digest;

	const size_t test_count =
	sizeof(tests) / sizeof(tests[0]);

	size_t passed = 0;

	for (size_t i = 0; i < test_count; ++i) {
		Sha512_224Calculate(
			tests[i].message,
			(uint32_t)strlen(tests[i].message),
						  &digest
		);

		if (hash_matches(&digest, tests[i].expected)) {
			printf("Test %zu PASSED\n", i);
			++passed;
		} else {
			printf("Test %zu FAILED\n", i);
		}
		printf("Expected: %s\n", tests[i].expected);
		printf("Got     : ");
		print_hash(&digest);
	}

	printf(
		"\nSHA512/224 tests: %zu/%zu passed\n",
		passed,
		test_count
	);

	return passed == test_count ? 0 : 1;
}
