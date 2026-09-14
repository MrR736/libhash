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

#if !HASH_USE_CUSTOM_MEM
#include <stdlib.h>
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
LIBHASH_INLINE_API int vigenere_key_value(char c) {
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a';
	return -1;
}

// Shift one alphabetic character.
LIBHASH_INLINE_API char vigenere_shift_char(char c, int shift) {
	shift %= 26;
	if (shift < 0) shift += 26;
	if (c >= 'A' && c <= 'Z') return (char)('A' + ((c - 'A' + shift) % 26));
	if (c >= 'a' && c <= 'z') return (char)('a' + ((c - 'a' + shift) % 26));
	return c;
}

/*
 * Check that the key contains at least one alphabetic
 * character.
 */
LIBHASH_INLINE_API int vigenere_validate_key(const char *key) {
	if (!key) return 0;
	for (size_t i = 0; key[i] != '\0'; ++i) {
		if (vigenere_key_value(key[i]) >= 0) return 1;
	}
	return 0;
}

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
LIBHASH_INLINE_API char* vigenere_encrypt(const char *str, const char *key) {
	if (!str || !key) return NULL;
	if (!vigenere_validate_key(key)) return NULL;
	size_t len = strlen(str);
	char *out = (char *)malloc(len + 1);
	if (!out) return NULL;
	size_t key_pos = 0;
	for (size_t i = 0; i < len; ++i) {
		const char c = str[i];
		if (c >= 'A' && c <= 'Z') {
			int shift;
			do {
				shift = vigenere_key_value(key[key_pos++]);
				if (key[key_pos - 1] == '\0') {
					key_pos = 0;
					shift = vigenere_key_value(key[key_pos++]);
				}
			} while (shift < 0);
			out[i] = vigenere_shift_char(c, shift);
		} else if (c >= 'a' && c <= 'z') {
			int shift;
			do {
				shift = vigenere_key_value(key[key_pos++]);
				if (key[key_pos - 1] == '\0') {
					key_pos = 0;
					shift = vigenere_key_value(key[key_pos++]);
				}
			} while (shift < 0);
			out[i] = vigenere_shift_char(c, shift);
		} else out[i] = c;
	}

	out[len] = '\0';

	return out;
}

// String decryption
LIBHASH_INLINE_API char* vigenere_decrypt(const char *str, const char *key) {
	if (!str || !key) return NULL;
	if (!vigenere_validate_key(key)) return NULL;
	size_t len = strlen(str);
	char *out = (char *)malloc(len + 1);
	if (!out)return NULL;
	size_t key_pos = 0;
	for (size_t i = 0; i < len; ++i) {
		const char c = str[i];
		if (c >= 'A' && c <= 'Z') {
			int shift;
			do {
				shift = vigenere_key_value(key[key_pos++]);
				if (key[key_pos - 1] == '\0') {
					key_pos = 0;
					shift = vigenere_key_value(key[key_pos++]);
				}
			} while (shift < 0);
			out[i] = vigenere_shift_char(c, -shift);
		} else if (c >= 'a' && c <= 'z') {
			int shift;
			do {
				shift = vigenere_key_value(key[key_pos++]);
				if (key[key_pos - 1] == '\0') {
					key_pos = 0;
					shift = vigenere_key_value(key[key_pos++]);
				}
			} while (shift < 0);
			out[i] = vigenere_shift_char(c, -shift);
		} else out[i] = c;
	}
	out[len] = '\0';
	return out;
}

// In-place encryption
LIBHASH_INLINE_API int vigenere_encrypt_inplace(char *str,size_t len,const char *key) {
	if ((!str && len != 0) || !key) return VIGENERE_ERR_INVALID_ARG;
	if (!vigenere_validate_key(key)) return VIGENERE_ERR_BAD_KEY;
	size_t key_pos = 0;
	for (size_t i = 0; i < len; ++i) {
		const char c = str[i];
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			int shift;
			do {
				shift = vigenere_key_value(key[key_pos++]);
				if (key[key_pos - 1] == '\0') {
					key_pos = 0;
					shift = vigenere_key_value(key[key_pos++]);
				}
			} while (shift < 0);
			str[i] = vigenere_shift_char(c, shift);
		}
	}
	return VIGENERE_SUCCESS;
}

// In-place decryption
LIBHASH_INLINE_API int vigenere_decrypt_inplace(char *str,size_t len,const char *key) {
	if ((!str && len != 0) || !key) return VIGENERE_ERR_INVALID_ARG;
	if (!vigenere_validate_key(key)) return VIGENERE_ERR_BAD_KEY;
	size_t key_pos = 0;
	for (size_t i = 0; i < len; ++i) {
		const char c = str[i];
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			int shift;
			do {
				shift = vigenere_key_value(key[key_pos++]);
				if (key[key_pos - 1] == '\0') {
					key_pos = 0;
					shift = vigenere_key_value(key[key_pos++]);
				}
			} while (shift < 0);
			str[i] = vigenere_shift_char(c, -shift);
		}
	}
	return VIGENERE_SUCCESS;
}

/*
 * Binary-safe buffer encryption
 *
 * Only ASCII alphabetic bytes are transformed.
 * Other bytes remain unchanged.
 */
LIBHASH_INLINE_API int vigenere_encrypt_buffer(const void *data,size_t len,const char *key,void **out) {
	if ((!data && len != 0) || !key || !out) return VIGENERE_ERR_INVALID_ARG;
	if (!vigenere_validate_key(key)) return VIGENERE_ERR_BAD_KEY;
	uint8_t *result = (uint8_t *)malloc(len);
	if (!result && len != 0) return VIGENERE_ERR_ALLOC_FAIL;
	const uint8_t *input = (const uint8_t *)data;
	size_t key_pos = 0;
	for (size_t i = 0; i < len; ++i) {
		const char c = (char)input[i];
		result[i] = input[i];
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			int shift;
			do {
				shift = vigenere_key_value(key[key_pos++]);
				if (key[key_pos - 1] == '\0') {
					key_pos = 0;
					shift = vigenere_key_value(key[key_pos++]);
				}
			} while (shift < 0);
			result[i] = (uint8_t)vigenere_shift_char(c, shift);
		}
	}
	*out = result;
	return VIGENERE_SUCCESS;
}

// Binary-safe buffer decryption
LIBHASH_INLINE_API int vigenere_decrypt_buffer(const void *data,size_t len,const char *key,void **out) {
	if ((!data && len != 0) || !key || !out) return VIGENERE_ERR_INVALID_ARG;
	if (!vigenere_validate_key(key)) return VIGENERE_ERR_BAD_KEY;
	uint8_t *result = (uint8_t *)malloc(len);
	if (!result && len != 0) return VIGENERE_ERR_ALLOC_FAIL;
	const uint8_t *input = (const uint8_t *)data;
	size_t key_pos = 0;
	for (size_t i = 0; i < len; ++i) {
		const char c = (char)input[i];
		result[i] = input[i];
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			int shift;
			do {
				shift = vigenere_key_value(key[key_pos++]);
				if (key[key_pos - 1] == '\0') {
					key_pos = 0;
					shift = vigenere_key_value(key[key_pos++]);
				}
			} while (shift < 0);
			result[i] =(uint8_t)vigenere_shift_char(c, -shift);
		}
	}
	*out = result;
	return VIGENERE_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#endif /* __VIGENERE_H__ */
