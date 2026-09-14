#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>

#include "sha3-512.h"

static void print_hash(const SHA3_512_HASH* digest) {
	for (int i = 0; i < SHA3_512_HASH_SIZE; ++i)
		printf("%02x", digest->bytes[i]);

	printf("\n");
}

static int hash_matches(
	const SHA3_512_HASH* digest,
	const char* expectedHex
) {
	char hashHex[SHA3_512_HASH_SIZE * 2 + 1] = {0};

	for (int i = 0; i < SHA3_512_HASH_SIZE; ++i)
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
			"a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
			"15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
		},
		{
			"abc",
			"b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
			"10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
		},
		{
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			"04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636d"
			"ee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e"
		},
		{
			"The quick brown fox jumps over the lazy dog",
			"01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff"
			"23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450"
		},
		{
			"The quick brown fox jumps over the lazy cog",
			"28e361fe8c56e617caa56c28c7c36e5c13be552b77081be82b642f08bb7ef085"
			"b9a81910fe98269386b9aacfd2349076c9506126e198f6f6ad44c12017ca77b1"
		},
	};

	SHA3_512_HASH digest;

	const size_t test_count =
	sizeof(tests) / sizeof(tests[0]);

	size_t passed = 0;

	for (size_t i = 0; i < test_count; ++i) {
		Sha3_512Calculate(
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
		"\nSHA3-512 tests: %zu/%zu passed\n",
		passed,
		test_count
	);

	return passed == test_count ? 0 : 1;
}
