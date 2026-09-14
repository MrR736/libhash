/**
 * WjCryptLib_atbash
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

#ifndef __ATBASH_H__
#define __ATBASH_H__

#include <stdint.h>

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
#ifdef _WIN32
#define LIBHASH_EXPORT __declspec(dllexport)
#else
#define LIBHASH_EXPORT LIBHASH_VISIBILITY(default)
#endif
#endif

#ifndef LIBHASH_IMPORT
#ifdef _WIN32
#define LIBHASH_IMPORT __declspec(dllimport)
#else
#define LIBHASH_IMPORT LIBHASH_VISIBILITY(default)
#endif
#endif

#ifndef LIBHASH_INLINE_API
#define LIBHASH_INLINE_API static inline
#endif

#define ATBASH_SUCCESS			0
#define ATBASH_ERR_INVALID_ARG	-1
#define ATBASH_ERR_ALLOC_FAIL	-2

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Single character
 *
 * A -> Z
 * B -> Y
 * C -> X
 *
 * a -> z
 * b -> y
 * c -> x
 */
LIBHASH_INLINE_API char atbash_char(char c) {
	if (c >= 'A' && c <= 'Z') return (char)('Z' - (c - 'A'));
	if (c >= 'a' && c <= 'z') return (char)('z' - (c - 'a'));
	return c;
}

/*
 * In-place transformation
 *
 * Atbash is symmetric:
 *
 * encrypt(encrypt(x)) == x
 *
 * Therefore the same function performs both encryption
 * and decryption.
 *
 */
LIBHASH_INLINE_API int atbash_inplace(char *str, size_t len) {
	if (!str && len != 0) return ATBASH_ERR_INVALID_ARG;
	for (size_t i = 0; i < len; ++i) str[i] = atbash_char(str[i]);
	return ATBASH_SUCCESS;
}

/*
 * String transformation
 *
 * Returns a newly allocated NUL-terminated string.
 * Caller must free() the returned buffer.
 */
LIBHASH_INLINE_API char* atbash(const char *str) {
	if (!str) return NULL;
	size_t len = strlen(str);
	char *out = (char *)malloc(len + 1);
	if (!out) return NULL;
	for (size_t i = 0; i < len; ++i) out[i] = atbash_char(str[i]);
	out[len] = '\0';
	return out;
}

/*
 * Buffer transformation
 *
 * Length is explicit, so arbitrary buffers can be processed.
 *
 * Note:
 * Atbash only transforms ASCII alphabetic bytes. All other
 * bytes are copied unchanged.
 */
LIBHASH_INLINE_API int atbash_buffer(const void *data,size_t len,void **out) {
	if ((!data && len != 0) || !out) return ATBASH_ERR_INVALID_ARG;
	uint8_t *result = (uint8_t *)malloc(len);
	if (!result && len != 0) return ATBASH_ERR_ALLOC_FAIL;
	const uint8_t *input = (const uint8_t *)data;
	for (size_t i = 0; i < len; ++i) result[i] = (uint8_t)atbash_char((char)input[i]);
	*out = result;
	return ATBASH_SUCCESS;
}

/*
 * Explicit aliases
 *
 * Atbash encryption and decryption are identical operations.
 */
LIBHASH_INLINE_API char* atbash_encrypt(const char *str) {
	return atbash(str);
}

LIBHASH_INLINE_API char* atbash_decrypt(const char *str) {
	return atbash(str);
}

LIBHASH_INLINE_API int atbash_encrypt_inplace(char *str, size_t len) {
	return atbash_inplace(str, len);
}

LIBHASH_INLINE_API int atbash_decrypt_inplace(char *str, size_t len) {
	return atbash_inplace(str, len);
}

LIBHASH_INLINE_API int atbash_encrypt_buffer(const void *data,size_t len,void **out) {
	return atbash_buffer(data, len, out);
}

LIBHASH_INLINE_API int atbash_decrypt_buffer(const void *data,size_t len,void **out) {
	return atbash_buffer(data, len, out);
}

#ifdef __cplusplus
}
#endif

#endif /* __ATBASH_H__ */
