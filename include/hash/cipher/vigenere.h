/**
 * WjCryptLib_vigenere
 *
 * Copyright (C) 2026 MrR736 <MrR736@users.github.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __VIGENERE_H__
#define __VIGENERE_H__

#include <stdint.h>
#include <stddef.h>

#define VIGENERE_SUCCESS          0
#define VIGENERE_ERR_INVALID_ARG -1
#define VIGENERE_ERR_ALLOC_FAIL  -2
#define VIGENERE_ERR_BAD_KEY     -3

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Convert an ASCII alphabetic character to a key value:
 *
 * A/a -> 0
 * B/b -> 1
 * ...
 * Z/z -> 25
 *
 * Returns -1 for non-alphabetic characters.
 */
extern int vigenere_key_value(char c);

// Shift one alphabetic character.
extern char vigenere_shift_char(char c, int shift);

/*
 * Check that the key contains at least one alphabetic
 * character.
 */
extern int vigenere_validate_key(const char *key);

/*
 * String encryption
 *
 * Non-alphabetic characters are copied unchanged and do not
 * consume a character from the Vigenère key.
 *
 * Example:
 *   plaintext:	HELLO WORLD
 *   key:		KEYKEYKEYK
 */
extern char* vigenere_encrypt(const char *str, const char *key);

// String decryption
extern char* vigenere_decrypt(const char *str, const char *key);

// In-place encryption
extern int vigenere_encrypt_inplace(char *str,size_t len,const char *key);

// In-place decryption
extern int vigenere_decrypt_inplace(char *str,size_t len,const char *key);

/*
 * Binary-safe buffer encryption
 *
 * Only ASCII alphabetic bytes are transformed.
 * Other bytes remain unchanged.
 */
extern int vigenere_encrypt_buffer(const void *data,size_t len,const char *key,void **out);

// Binary-safe buffer decryption
extern int vigenere_decrypt_buffer(const void *data,size_t len,const char *key,void **out);

#ifdef __cplusplus
}
#endif

#endif /* __VIGENERE_H__ */
