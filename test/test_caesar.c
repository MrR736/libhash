#include "caesar.h"
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	char *encrypted =
	caesar_encrypt("Hello, World!", 3);

	if (!encrypted)
		return 1;

	printf("Encrypted: %s\n", encrypted);

	char *decrypted =
	caesar_decrypt(encrypted, 3);

	if (!decrypted) {
		free(encrypted);
		return 1;
	}

	printf("Decrypted: %s\n", decrypted);

	free(encrypted);
	free(decrypted);

	return 0;
}
