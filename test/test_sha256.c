#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "sha256.h"  // Ensure it includes the functions you've defined

static void print_hash(SHA256_HASH* digest) {
	for (int i = 0; i < SHA256_HASH_SIZE; ++i)
		printf("%02x", digest->bytes[i]);
	printf("\n");
}

static int hash_matches(SHA256_HASH* digest, const char* expectedHex) {
	char hashHex[65] = {0};
	for (int i = 0; i < SHA256_HASH_SIZE; ++i)
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
			"e3b0c44298fc1c149afbf4c8996fb924"
			"27ae41e4649b934ca495991b7852b855"
		},
		{
			"abc",
			"ba7816bf8f01cfea414140de5dae2223"
			"b00361a396177a9cb410ff61f20015ad"
		},
		{
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			"248d6a61d20638b8e5c026930c3e6039"
			"a33ce45964ff2167f6ecedd419db06c1"
		},
		{
			"The quick brown fox jumps over the lazy dog",
			"d7a8fbb307d7809469ca9abcb0082e4f"
			"8d5651e46d3cdb762d02d0bf37c9e592"
		},
		{
			"The quick brown fox jumps over the lazy cog",
			"e4c4d8f3bf76b692de791a173e053211"
			"50f7a345b46484fe427f6acc7ecc81be"
		},
	};

	SHA256_HASH digest;
	int all_passed = 1;

	for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); ++i) {
		Sha256Calculate(tests[i].message, (uint32_t)strlen(tests[i].message), &digest);
		if (hash_matches(&digest, tests[i].expected)) {
			printf("Test %zu PASSED\n", i);
		} else {
			printf("Test %zu FAILED\n", i);
			printf("Expected: %s\n", tests[i].expected);
			printf("Got	 : ");
			print_hash(&digest);
			all_passed = 0;
		}
	}

	return all_passed ? 0 : 1;
}
