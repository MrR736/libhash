#include "atbash.h"
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	char *encrypted = atbash_encrypt("Hello, World!");

	if (!encrypted)
		return 1;

	printf("Encrypted: %s\n", encrypted);

	char *decrypted = atbash_decrypt(encrypted);

	if (!decrypted) {
		free(encrypted);
		return 1;
	}

	printf("Decrypted: %s\n", decrypted);

	free(encrypted);
	free(decrypted);

	return 0;
}
