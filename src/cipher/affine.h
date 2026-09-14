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

#if !HASH_USE_CUSTOM_MEM
# include <stdlib.h>
# ifdef _WIN32
#  include <string.h>
# else
#  include <memory.h>
# endif
#endif

#if defined(_MSC_VER) && _MSC_VER < 1900 && !defined(inline)
#define inline __inline
#endif

#ifndef LIBHASH_VISIBILITY
#if (defined(__GNUC__) &&  (__GNUC__ >= 4) && (__GNUC_MINOR__ > 2)) || __has_attribute(visibility)
#define LIBHASH_VISIBILITY(V) __attribute__ ((visibility (#V)))
#else
#define LIBHASH_VISIBILITY(V)
#endif
#endif

#ifndef LIBHASH_EXPORT
# ifdef _WIN32
#  define LIBHASH_EXPORT __declspec(dllexport)
# else
#  define LIBHASH_EXPORT LIBHASH_VISIBILITY(default)
# endif
#endif

#ifndef LIBHASH_IMPORT
# ifdef _WIN32
#  define LIBHASH_IMPORT __declspec(dllimport)
# else
#  define LIBHASH_IMPORT LIBHASH_VISIBILITY(default)
# endif
#endif

#ifndef LIBHASH_INLINE_API
#define LIBHASH_INLINE_API static inline
#endif

#define hash_c_cast(t,p)	((t)(intptr_t)(p))
#define uhash_c_cast(t,p)	((t)(uintptr_t)(p))

#ifdef __cplusplus
#define hash_cast(t,p) static_cast<t>(p)
#define uhash_cast(t,p) reinterpret_cast<t>(p)
#else
#define hash_cast hash_c_cast
#define uhash_cast uhash_c_cast
#endif

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
LIBHASH_INLINE_API int affine_gcd(int a, int b) {
	if (a < 0) a = -a;
	if (b < 0) b = -b;
	while (b != 0) {
		int t = a % b;
		a = b;
		b = t;
	}
	return a;
}

// Normalize a value into the range [0, 25].
LIBHASH_INLINE_API int affine_mod26(int value) {
	value %= AFFINE_ALPHABET_SIZE;
	if (value < 0) value += AFFINE_ALPHABET_SIZE;
	return value;
}

/*
 * Calculate the modular multiplicative inverse:
 *
 *     a * inverse(a) = 1 (mod 26)
 *
 * Returns -1 if no inverse exists.
 */
LIBHASH_INLINE_API int affine_mod_inverse(int a) {
	int i;
	a = affine_mod26(a);
	for (i = 1; i < AFFINE_ALPHABET_SIZE; ++i) {
		if ((a * i) % AFFINE_ALPHABET_SIZE == 1) return i;
	}
	return -1;
}

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
LIBHASH_INLINE_API int affine_validate_key(int a, int b) {
	(void)b;
	a = affine_mod26(a);
	if (affine_gcd(a, AFFINE_ALPHABET_SIZE) != 1) return AFFINE_ERR_BAD_KEY;
	return AFFINE_SUCCESS;
}

/*
 * Encrypt a single ASCII alphabetic character.
 *
 * Uppercase characters remain uppercase.
 * Lowercase characters remain lowercase.
 * Non-alphabetic characters are unchanged.
 */
LIBHASH_INLINE_API char affine_encrypt_char(char c, int a, int b) {
	int x;
	int y;
	if (c >= 'A' && c <= 'Z') {
		x = c - 'A';
		y = affine_mod26(a * x + b);
		return (char)('A' + y);
	}
	if (c >= 'a' && c <= 'z') {
		x = c - 'a';
		y = affine_mod26(a * x + b);
		return (char)('a' + y);
	}
	return c;
}

// Decrypt a single ASCII alphabetic character.
LIBHASH_INLINE_API char affine_decrypt_char(char c, int a, int b) {
	int inverse;
	int x;
	int y;
	inverse = affine_mod_inverse(a);
	if (inverse < 0) return c;
	if (c >= 'A' && c <= 'Z') {
		x = c - 'A';
		y = affine_mod26(inverse * (x - b));
		return (char)('A' + y);
	}
	if (c >= 'a' && c <= 'z') {
		x = c - 'a';
		y = affine_mod26(inverse * (x - b));
		return (char)('a' + y);
	}
	return c;
}

// Encrypt a string in-place.
LIBHASH_INLINE_API int affine_encrypt_inplace(char *text,int a,int b) {
	size_t i;
	if (text == NULL) return AFFINE_ERR_INVALID_ARG;
	if (affine_validate_key(a, b) != AFFINE_SUCCESS) return AFFINE_ERR_BAD_KEY;
	for (i = 0; text[i] != '\0'; ++i) text[i] = affine_encrypt_char(text[i], a, b);
	return AFFINE_SUCCESS;
}

// Decrypt a string in-place.
LIBHASH_INLINE_API int affine_decrypt_inplace(char *text,int a,int b) {
	size_t i;
	if (text == NULL) return AFFINE_ERR_INVALID_ARG;
	if (affine_validate_key(a, b) != AFFINE_SUCCESS) return AFFINE_ERR_BAD_KEY;
	for (i = 0; text[i] != '\0'; ++i) text[i] = affine_decrypt_char(text[i], a, b);
	return AFFINE_SUCCESS;
}

/*
 * Encrypt a string and allocate the result.
 *
 * The caller owns the returned buffer and must free() it.
 */
LIBHASH_INLINE_API int affine_encrypt(const char *text,int a,int b,char **output) {
	size_t length;
	size_t i;
	char *result;
	if (text == NULL || output == NULL) return AFFINE_ERR_INVALID_ARG;
	*output = NULL;
	if (affine_validate_key(a, b) != AFFINE_SUCCESS) return AFFINE_ERR_BAD_KEY;
	length = strlen(text);
	result = (char *)malloc(length + 1);
	if (result == NULL) return AFFINE_ERR_ALLOC_FAIL;
	for (i = 0; i < length; ++i) result[i] = affine_encrypt_char(text[i], a, b);
	result[length] = '\0';
	*output = result;
	return AFFINE_SUCCESS;
}

/*
 * Decrypt a string and allocate the result.
 *
 * The caller owns the returned buffer and must free() it.
 */
LIBHASH_INLINE_API int affine_decrypt(const char *text,int a,int b,char **output) {
	size_t length;
	size_t i;
	char *result;
	if (text == NULL || output == NULL) return AFFINE_ERR_INVALID_ARG;
	*output = NULL;
	if (affine_validate_key(a, b) != AFFINE_SUCCESS) return AFFINE_ERR_BAD_KEY;
	length = strlen(text);
	result = (char *)malloc(length + 1);
	if (result == NULL) return AFFINE_ERR_ALLOC_FAIL;
	for (i = 0; i < length; ++i) result[i] = affine_decrypt_char(text[i], a, b);
	result[length] = '\0';
	*output = result;
	return AFFINE_SUCCESS;
}

/*
 * Encrypt a buffer.
 *
 * The output buffer may be the same as the input buffer.
 */
LIBHASH_INLINE_API int affine_encrypt_buffer(const uint8_t *input,size_t length,int a,int b,uint8_t *output) {
	size_t i;
	if ((input == NULL && length != 0) || output == NULL) return AFFINE_ERR_INVALID_ARG;
	if (affine_validate_key(a, b) != AFFINE_SUCCESS) return AFFINE_ERR_BAD_KEY;
	for (i = 0; i < length; ++i) output[i] = (uint8_t)affine_encrypt_char((char)input[i], a, b);
	return AFFINE_SUCCESS;
}

/*
 * Decrypt a buffer.
 *
 * The output buffer may be the same as the input buffer.
 */
LIBHASH_INLINE_API int affine_decrypt_buffer(const uint8_t *input,size_t length,int a,int b,uint8_t *output) {
	size_t i;
	if ((input == NULL && length != 0) || output == NULL) return AFFINE_ERR_INVALID_ARG;
	if (affine_validate_key(a, b) != AFFINE_SUCCESS) return AFFINE_ERR_BAD_KEY;
	for (i = 0; i < length; ++i) output[i] = (uint8_t)affine_decrypt_char((char)input[i], a, b);
	return AFFINE_SUCCESS;
}

/*
 * Convenience aliases.
 */
#define affine_encrypt_string  affine_encrypt
#define affine_decrypt_string  affine_decrypt

#ifdef __cplusplus
}
#endif

#endif /* __AFFINE_H__ */
