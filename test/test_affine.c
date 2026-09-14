#include "affine.h"
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	char *encrypted = NULL;
	char *decrypted = NULL;

	affine_encrypt("Hello World!", 5, 8, &encrypted);
	printf("Encrypted: %s\n", encrypted);

	affine_decrypt(encrypted, 5, 8, &decrypted);
	printf("Decrypted: %s\n", decrypted);

	free(encrypted);
	free(decrypted);

	return 0;
}
