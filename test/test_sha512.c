#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "sha512.h" // Ensure your implementation is in this file

static void print_hash(SHA512_HASH* digest) {
	for (int i = 0; i < SHA512_HASH_SIZE; ++i)
		printf("%02x", digest->bytes[i]);
	printf("\n");
}

static int hash_matches(const SHA512_HASH* digest, const char* expectedHex) {
	char hashHex[129] = {0};
	for (int i = 0; i < SHA512_HASH_SIZE; ++i)
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
			"cf83e1357eefb8bd"
			"f1542850d66d8007"
			"d620e4050b5715dc"
			"83f4a921d36ce9ce"
			"47d0d13c5d85f2b0"
			"ff8318d2877eec2f"
			"63b931bd47417a81"
			"a538327af927da3e"
		},
		{
			"abc",
			"ddaf35a193617abacc417349ae204131"
			"12e6fa4e89a97ea20a9eeee64b55d39a"
			"2192992a274fc1a836ba3c23a3feebbd"
			"454d4423643ce80e2a9ac94fa54ca49f"
		},
		{
			"The quick brown fox jumps over the lazy dog",
			"07e547d9586f6a73f73fbac0435ed769"
			"51218fb7d0c8d788a309d785436bbb64"
			"2e93a252a954f23912547d1e8a3b5ed6"
			"e1bfd7097821233fa0538f3db854fee6"
		},
		{
			"The quick brown fox jumps over the lazy cog",
			"3eeee1d0e11733ef152a6c29503b3ae2"
			"0c4f1f3cda4cb26f1bc1a41f91c7fe4a"
			"b3bd86494049e201c4bd5155f31ecb7a"
			"3c8606843c4cc8dfcab7da11c8ae5045"
		},
		{
			"Hello World!",
			"861844d6704e8573fec34d967e20bcfe"
			"f3d424cf48be04e6dc08f2bd58c72974"
			"3371015ead891cc3cf1c9d34b49264b5"
			"10751b1ff9e537937bc46b5d6ff4ecc8"
		}
	};

	SHA512_HASH digest;
	int all_passed = 1;

	for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); ++i) {
		Sha512Calculate(tests[i].message, (uint32_t)strlen(tests[i].message), &digest);
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
