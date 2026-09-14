#include "customcipher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Simple XOR custom cipher used for testing.
 *
 * XOR is symmetrical, so the same operation is used
 * for encryption and decryption.
 */
static int test_encrypt(
	const void *data,
	size_t len,
	void **out,
	size_t *out_len)
{
	const unsigned char *input;
	unsigned char *output;

	if ((!data && len != 0) || !out || !out_len)
		return CUSTOMCIPHER_ERR_INVALID_ARG;

	*out = NULL;
	*out_len = 0;

	if (len == 0)
		return CUSTOMCIPHER_SUCCESS;

	output = (unsigned char *)malloc(len);

	if (!output)
		return CUSTOMCIPHER_ERR_ALLOC_FAIL;

	input = (const unsigned char *)data;

	for (size_t i = 0; i < len; ++i)
		output[i] = input[i] ^ 0xAA;

	*out = output;
	*out_len = len;

	return CUSTOMCIPHER_SUCCESS;
}

static int test_decrypt(
	const void *data,
	size_t len,
	void **out,
	size_t *out_len)
{
	return test_encrypt(data, len, out, out_len);
}

static int test_basic(void)
{
	const char plaintext[] = "Hello World!";
	const size_t plaintext_len = sizeof(plaintext) - 1;

	customcipher cipher;

	void *encrypted = NULL;
	void *decrypted = NULL;

	size_t encrypted_len = 0;
	size_t decrypted_len = 0;

	int result;

	printf("Test: basic encrypt/decrypt\n");

	result = customcipher_init(
		&cipher,
		test_encrypt,
		test_decrypt
	);

	if (result != CUSTOMCIPHER_SUCCESS) {
		printf("FAIL: customcipher_init() returned %d\n", result);
		return 1;
	}

	result = customcipher_encrypt(
		&cipher,
		plaintext,
		plaintext_len,
		&encrypted,
		&encrypted_len
	);

	if (result != CUSTOMCIPHER_SUCCESS) {
		printf("FAIL: encryption returned %d\n", result);
		return 1;
	}

	if (encrypted_len != plaintext_len) {
		printf(
			"FAIL: encrypted length = %zu, expected %zu\n",
		 encrypted_len,
		 plaintext_len
		);

		free(encrypted);
		return 1;
	}

	result = customcipher_decrypt(
		&cipher,
		encrypted,
		encrypted_len,
		&decrypted,
		&decrypted_len
	);

	if (result != CUSTOMCIPHER_SUCCESS) {
		printf("FAIL: decryption returned %d\n", result);
		free(encrypted);
		return 1;
	}

	if (decrypted_len != plaintext_len) {
		printf(
			"FAIL: decrypted length = %zu, expected %zu\n",
		 decrypted_len,
		 plaintext_len
		);

		free(encrypted);
		free(decrypted);
		return 1;
	}

	if (memcmp(decrypted, plaintext, plaintext_len) != 0) {
		printf("FAIL: decrypted data does not match plaintext\n");

		free(encrypted);
		free(decrypted);
		return 1;
	}

	printf("PASS\n");
	printf("Plaintext : %s\n", plaintext);

	printf("Encrypted : ");
	for (size_t i = 0; i < encrypted_len; ++i)
		printf("%02X ", ((unsigned char *)encrypted)[i]);
	printf("\n");

	printf("Decrypted : %.*s\n",
		   (int)decrypted_len,
		   (char *)decrypted
	);

	free(encrypted);
	free(decrypted);

	return 0;
}

static int test_empty(void)
{
	customcipher cipher;

	void *encrypted = NULL;
	void *decrypted = NULL;

	size_t encrypted_len = 123;
	size_t decrypted_len = 123;

	int result;

	printf("Test: empty input\n");

	if (customcipher_init(
		&cipher,
		test_encrypt,
		test_decrypt
	) != CUSTOMCIPHER_SUCCESS) {
		printf("FAIL: initialization\n");
		return 1;
	}

	result = customcipher_encrypt(
		&cipher,
		NULL,
		0,
		&encrypted,
		&encrypted_len
	);

	if (result != CUSTOMCIPHER_SUCCESS) {
		printf("FAIL: empty encryption returned %d\n", result);
		return 1;
	}

	if (encrypted_len != 0) {
		printf("FAIL: expected encrypted length 0\n");
		free(encrypted);
		return 1;
	}

	result = customcipher_decrypt(
		&cipher,
		NULL,
		0,
		&decrypted,
		&decrypted_len
	);

	if (result != CUSTOMCIPHER_SUCCESS) {
		printf("FAIL: empty decryption returned %d\n", result);
		free(encrypted);
		return 1;
	}

	if (decrypted_len != 0) {
		printf("FAIL: expected decrypted length 0\n");
		free(encrypted);
		free(decrypted);
		return 1;
	}

	free(encrypted);
	free(decrypted);

	printf("PASS\n");

	return 0;
}

static int test_invalid_arguments(void)
{
	customcipher cipher;

	void *output = NULL;
	size_t output_len = 0;

	int result;

	printf("Test: invalid arguments\n");

	if (customcipher_init(
		&cipher,
		test_encrypt,
		test_decrypt
	) != CUSTOMCIPHER_SUCCESS) {
		printf("FAIL: initialization\n");
		return 1;
	}

	result = customcipher_encrypt(
		NULL,
		"test",
		4,
		&output,
		&output_len
	);

	if (result != CUSTOMCIPHER_ERR_INVALID_ARG) {
		printf(
			"FAIL: expected CUSTOMCIPHER_ERR_INVALID_ARG, got %d\n",
		 result
		);
		return 1;
	}

	result = customcipher_encrypt(
		&cipher,
		NULL,
		4,
		&output,
		&output_len
	);

	if (result != CUSTOMCIPHER_ERR_INVALID_ARG) {
		printf(
			"FAIL: NULL data returned %d\n",
		 result
		);
		return 1;
	}

	result = customcipher_encrypt(
		&cipher,
		"test",
		4,
		NULL,
		&output_len
	);

	if (result != CUSTOMCIPHER_ERR_INVALID_ARG) {
		printf(
			"FAIL: NULL output returned %d\n",
		 result
		);
		return 1;
	}

	result = customcipher_encrypt(
		&cipher,
		"test",
		4,
		&output,
		NULL
	);

	if (result != CUSTOMCIPHER_ERR_INVALID_ARG) {
		printf(
			"FAIL: NULL output length returned %d\n",
		 result
		);
		return 1;
	}

	printf("PASS\n");

	return 0;
}

static int test_binary_data(void)
{
	const unsigned char input[] = {
		0x00,
		0x01,
		0x7F,
		0x80,
		0xAA,
		0xFF
	};

	const size_t input_len = sizeof(input);

	customcipher cipher;

	void *encrypted = NULL;
	void *decrypted = NULL;

	size_t encrypted_len = 0;
	size_t decrypted_len = 0;

	printf("Test: binary data\n");

	if (customcipher_init(
		&cipher,
		test_encrypt,
		test_decrypt
	) != CUSTOMCIPHER_SUCCESS) {
		printf("FAIL: initialization\n");
		return 1;
	}

	if (customcipher_encrypt(
		&cipher,
		input,
		input_len,
		&encrypted,
		&encrypted_len
	) != CUSTOMCIPHER_SUCCESS) {
		printf("FAIL: binary encryption\n");
		return 1;
	}

	if (customcipher_decrypt(
		&cipher,
		encrypted,
		encrypted_len,
		&decrypted,
		&decrypted_len
	) != CUSTOMCIPHER_SUCCESS) {
		printf("FAIL: binary decryption\n");
		free(encrypted);
		return 1;
	}

	if (decrypted_len != input_len ||
		memcmp(decrypted, input, input_len) != 0) {
		printf("FAIL: binary data mismatch\n");

	free(encrypted);
	free(decrypted);

	return 1;
		}

		printf("PASS\n");

		free(encrypted);
		free(decrypted);

		return 0;
}

int main(void)
{
	int failures = 0;

	printf("=== WjCryptLib customcipher tests ===\n\n");

	failures += test_basic();
	failures += test_empty();
	failures += test_invalid_arguments();
	failures += test_binary_data();

	printf("\n");

	if (failures == 0) {
		printf("ALL TESTS PASSED\n");
		return 0;
	}

	printf("%d TEST(S) FAILED\n", failures);

	return 1;
}
