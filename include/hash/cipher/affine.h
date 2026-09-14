/*
 * WjCryptLib_affine
 *
 * Copyright (C) 2026 MrR736
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
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef __AFFINE_H__
#define __AFFINE_H__

#include <stdint.h>
#include <stddef.h>

#define AFFINE_SUCCESS			0
#define AFFINE_ERR_INVALID_ARG	-1
#define AFFINE_ERR_ALLOC_FAIL	-2
#define AFFINE_ERR_BAD_KEY		-3

#define AFFINE_ALPHABET_SIZE 26

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Greatest common divisor.
 */
extern int affine_gcd(int a, int b);

// Normalize a value into the range [0, 25].
extern int affine_mod26(int value);

/*
 * Calculate the modular multiplicative inverse:
 *
 *     a * inverse(a) = 1 (mod 26)
 *
 * Returns -1 if no inverse exists.
 */
extern int affine_mod_inverse(int a);

/*
 * Validate Affine cipher key.
 *
 * Encryption:
 *     E(x) = (a*x + b) mod 26
 *
 * Decryption:
 *
 *     D(x) = a^-1 * (x - b) mod 26
 *
 * 'a' must be relatively prime to 26.
 */
extern int affine_validate_key(int a, int b);

/*
 * Encrypt a single ASCII alphabetic character.
 *
 * Uppercase characters remain uppercase.
 * Lowercase characters remain lowercase.
 * Non-alphabetic characters are unchanged.
 */
extern char affine_encrypt_char(char c, int a, int b);

// Decrypt a single ASCII alphabetic character.
extern char affine_decrypt_char(char c, int a, int b);

// Encrypt a string in-place.
extern int affine_encrypt_inplace(char *text,int a,int b);

// Decrypt a string in-place.
extern int affine_decrypt_inplace(char *text,int a,int b);

/*
 * Encrypt a string and allocate the result.
 *
 * The caller owns the returned buffer and must free() it.
 */
extern int affine_encrypt(const char *text,int a,int b,char **output);

/*
 * Decrypt a string and allocate the result.
 *
 * The caller owns the returned buffer and must free() it.
 */
extern int affine_decrypt(const char *text,int a,int b,char **output);

/*
 * Encrypt a buffer.
 *
 * The output buffer may be the same as the input buffer.
 */
extern int affine_encrypt_buffer(const uint8_t *input,size_t length,int a,int b,uint8_t *output);

/*
 * Decrypt a buffer.
 *
 * The output buffer may be the same as the input buffer.
 */
extern int affine_decrypt_buffer(const uint8_t *input,size_t length,int a,int b,uint8_t *output);

/*
 * Convenience aliases.
 */
#define affine_encrypt_string  affine_encrypt
#define affine_decrypt_string  affine_decrypt

#ifdef __cplusplus
}
#endif

#endif /* __AFFINE_H__ */
