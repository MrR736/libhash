#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "sha0.h"  // Ensure this matches your actual header

static void print_hash(SHA0_HASH* digest) {
	for (int i = 0; i < SHA0_HASH_SIZE; ++i) {
		printf("%02x", digest->bytes[i]);
	}
	printf("\n");
}

// Utility: Compare a calculated SHA0 with a hex-encoded string
static int hash_matches(const SHA0_HASH* digest, const char* expectedHex) {
	char hashHex[129] = {0};
	for (int i = 0; i < SHA0_HASH_SIZE; ++i)
		sprintf(hashHex + i * 2, "%02x", digest->bytes[i]);
	return strcasecmp(hashHex, expectedHex) == 0;
}

int main(void) {
	struct {
		const char* message;
		const char* expected;  // Expected hex digest
	} tests[] = {
		{ "", "f96cea198ad1dd5617ac084a3d92c6107708c0ef" },
		{ "abc", "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880" },
		{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "d2516ee1acfa5baf33dfc1c471e438449ef134c8" },
		{ "The quick brown fox jumps over the lazy dog", "b03b401ba92d77666221e843feebf8c561cea5f7" },
		{ "The quick brown fox jumps over the lazy cog", "ff663342fe29cfb41198a86aed812f6fdac50ac7" },
	};

	SHA0_HASH digest;
	int all_passed = 0;
	for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); ++i) {
		Sha0Calculate(tests[i].message, (uint32_t)strlen(tests[i].message), &digest);
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
	return all_passed ? 0 : 0;
}
