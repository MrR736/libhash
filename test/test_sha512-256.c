#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>

#include "sha512-256.h"

static void print_hash(const SHA512_256_HASH* digest) {
	for (int i = 0; i < SHA512_256_HASH_SIZE; ++i)
		printf("%02x", digest->bytes[i]);

	printf("\n");
}

static int hash_matches(
	const SHA512_256_HASH* digest,
	const char* expectedHex
) {
	char hashHex[SHA512_256_HASH_SIZE * 2 + 1] = {0};

	for (int i = 0; i < SHA512_256_HASH_SIZE; ++i)
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
			"c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"
		},
		{
			"abc",
			"53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
		},
		{
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			"bde8e1f9f19bb9fd3406c90ec6bc47bd36d8ada9f11880dbc8a22a7078b6a461"
		},
		{
			"The quick brown fox jumps over the lazy dog",
			"dd9d67b371519c339ed8dbd25af90e976a1eeefd4ad3d889005e532fc5bef04d"
		},
		{
			"The quick brown fox jumps over the lazy cog",
			"cc8d255a7f2f38fd50388fd1f65ea7910835c5c1e73da46fba01ea50d5dd76fb"
		},
	};

	SHA512_256_HASH digest;

	const size_t test_count =
	sizeof(tests) / sizeof(tests[0]);

	size_t passed = 0;

	for (size_t i = 0; i < test_count; ++i) {
		Sha512_256Calculate(tests[i].message,(uint32_t)strlen(tests[i].message),&digest);
		if (hash_matches(&digest, tests[i].expected)) {
			printf("Test %zu PASSED\n", i);
			++passed;
		} else {
			printf("Test %zu FAILED\n", i);
			printf("Expected: %s\n", tests[i].expected);
			printf("Got     : ");
			print_hash(&digest);
		}
	}

	printf(
		"\nSHA512/256 tests: %zu/%zu passed\n",
		passed,
		test_count
	);

	return passed == test_count ? 0 : 1;
}
