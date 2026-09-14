/**
 * WjCryptLib_caesar
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

#ifndef __CAESAR_H__
#define __CAESAR_H__

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

#define hash_c_cast(t,p)	((t)(intptr_t)(p))
#define uhash_c_cast(t,p)	((t)(uintptr_t)(p))

#ifdef __cplusplus
#define hash_cast(t,p) static_cast<t>(p)
#define uhash_cast(t,p) reinterpret_cast<t>(p)
#else
#define hash_cast hash_c_cast
#define uhash_cast uhash_c_cast
#endif

#define CAESAR_SUCCESS		   0
#define CAESAR_ERR_INVALID_ARG -1
#define CAESAR_ERR_ALLOC_FAIL  -2

#ifdef __cplusplus
extern "C" {
#endif

LIBHASH_INLINE_API int caesar_normalize_shift(int shift) {
	shift %= 26;
	if (shift < 0) shift += 26;
	return shift;
}

LIBHASH_INLINE_API char caesar_shift_char(char c, int shift) {
	shift = caesar_normalize_shift(shift);
	if (c >= 'A' && c <= 'Z') return (char)('A' + ((c - 'A' + shift) % 26));
	if (c >= 'a' && c <= 'z') return (char)('a' + ((c - 'a' + shift) % 26));
	return c;
}

// Single character
LIBHASH_INLINE_API char caesar_encrypt_char(char c, int shift) {
	return caesar_shift_char(c, shift);
}

LIBHASH_INLINE_API char caesar_decrypt_char(char c, int shift) {
	return caesar_shift_char(c, -shift);
}

// In-place encryption
LIBHASH_INLINE_API int caesar_encrypt_inplace(char *str, size_t len, int shift) {
	if (!str && len != 0) return CAESAR_ERR_INVALID_ARG;
	shift = caesar_normalize_shift(shift);
	for (size_t i = 0; i < len; ++i) str[i] = caesar_shift_char(str[i], shift);
	return CAESAR_SUCCESS;
}

// In-place decryption
LIBHASH_INLINE_API int caesar_decrypt_inplace(char *str, size_t len, int shift) {
	if (!str && len != 0) return CAESAR_ERR_INVALID_ARG;
	shift = caesar_normalize_shift(shift);
	for (size_t i = 0; i < len; ++i) str[i] = caesar_shift_char(str[i], -shift);
	return CAESAR_SUCCESS;
}

/*
 * String encryption
 *
 * Returns a newly allocated NUL-terminated string.
 * Caller must free() the returned buffer.
 */
LIBHASH_INLINE_API char* caesar_encrypt(const char *str, int shift) {
	if (!str) return NULL;
	size_t len = strlen(str);
	char *out = (char *)malloc(len + 1);
	if (!out) return NULL;
	for (size_t i = 0; i < len; ++i) out[i] = caesar_shift_char(str[i], shift);
	out[len] = '\0';
	return out;
}

/*
 * String decryption
 *
 * Returns a newly allocated NUL-terminated string.
 * Caller must free() the returned buffer.
 */
LIBHASH_INLINE_API char *caesar_decrypt(const char *str, int shift) {
	if (!str) return NULL;
	size_t len = strlen(str);
	char *out = (char *)malloc(len + 1);
	if (!out) return NULL;
	for (size_t i = 0; i < len; ++i) out[i] = caesar_shift_char(str[i], -shift);
	out[len] = '\0';
	return out;
}

/*
 * Buffer encryption
 *
 * Works with binary-safe buffers because length is explicit.
 */
LIBHASH_INLINE_API int caesar_encrypt_buffer(const void *data,size_t len,int shift,void **out) {
	if ((!data && len != 0) || !out) return CAESAR_ERR_INVALID_ARG;
	uint8_t *result = (uint8_t *)malloc(len);
	if (!result && len != 0) return CAESAR_ERR_ALLOC_FAIL;
	const uint8_t *input = (const uint8_t *)data;
	shift = caesar_normalize_shift(shift);
	for (size_t i = 0; i < len; ++i) result[i] = (uint8_t)caesar_shift_char((char)input[i],shift);
	*out = result;
	return CAESAR_SUCCESS;
}

// Buffer decryption
LIBHASH_INLINE_API int caesar_decrypt_buffer(const void *data,size_t len,int shift,void **out) {
	if ((!data && len != 0) || !out) return CAESAR_ERR_INVALID_ARG;
	uint8_t *result = (uint8_t *)malloc(len);
	if (!result && len != 0) return CAESAR_ERR_ALLOC_FAIL;
	const uint8_t *input = (const uint8_t *)data;
	shift = caesar_normalize_shift(shift);
	for (size_t i = 0; i < len; ++i) result[i] = (uint8_t)caesar_shift_char((char)input[i],-shift);
	*out = result;
	return CAESAR_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#endif /* __CAESAR_H__ */
