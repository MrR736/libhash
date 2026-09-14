#include "vigenere.h"
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	const char *text = "Attack at Dawn!";
	const char *key  = "LEMON";

	char *encrypted =
	vigenere_encrypt(text, key);

	if (!encrypted)
		return 1;

	printf("Encrypted: %s\n", encrypted);

	char *decrypted =
	vigenere_decrypt(encrypted, key);

	if (!decrypted) {
		free(encrypted);
		return 1;
	}

	printf("Decrypted: %s\n", decrypted);

	free(encrypted);
	free(decrypted);

	return 0;
}
