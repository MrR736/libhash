#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>

#include "sha3-256.h"

static void print_hash(const SHA3_256_HASH* digest) {
	for (int i = 0; i < SHA3_256_HASH_SIZE; ++i)
		printf("%02x", digest->bytes[i]);

	printf("\n");
}

static int hash_matches(
	const SHA3_256_HASH* digest,
	const char* expectedHex
) {
	char hashHex[SHA3_256_HASH_SIZE * 2 + 1] = {0};

	for (int i = 0; i < SHA3_256_HASH_SIZE; ++i)
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
			"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
		},
		{
			"abc",
			"3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
		},
		{
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			"41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"
		},
		{
			"The quick brown fox jumps over the lazy dog",
			"69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04"
		},
		{
			"The quick brown fox jumps over the lazy cog",
			"cc80b0b13ba89613d93f02ee7ccbe72ee26c6edfe577f22e63a1380221caedbc"
		},
	};

	SHA3_256_HASH digest;

	const size_t test_count =
	sizeof(tests) / sizeof(tests[0]);

	size_t passed = 0;

	for (size_t i = 0; i < test_count; ++i) {
		Sha3_256Calculate(tests[i].message,(uint32_t)strlen(tests[i].message),&digest);
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
		"\nSHA3-256 tests: %zu/%zu passed\n",
		passed,
		test_count
	);

	return passed == test_count ? 0 : 1;
}
