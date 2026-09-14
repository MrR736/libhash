#include "playfair.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(void) {
	const char *plaintext = "INSTRUMENTS";
	const char *key = "MONARCHY";

	char matrix[26];

	if (playfair_matrix_string(key, matrix) != PLAYFAIR_SUCCESS)
		return 1;

	printf("Matrix:\n");

	for (int i = 0; i < 25; ++i) {
		printf("%c ", matrix[i]);

		if ((i + 1) % 5 == 0)
			printf("\n");
	}

	char *encrypted = playfair_encrypt(plaintext, key);

	if (!encrypted)
		return 1;

	printf("PlainText: %s\n", plaintext);
	printf("Encrypted: %s\n", encrypted);

	char *decrypted =
	playfair_decrypt(encrypted, key);

	if (decrypted) {
		size_t decrypted_len = strlen(decrypted);
		playfair_remove_padding(decrypted, &decrypted_len);
		printf("Decrypted: %s\n", decrypted);
	} else {
		printf("Decrypted: %s\n", decrypted);
		free(encrypted);
		return 1;
	}


	free(encrypted);
	free(decrypted);

	return 0;
}
