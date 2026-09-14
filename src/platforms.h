/**
 * WjCryptLib_Platforms
 *
 * Copyright (C) 2025 MrR736 <MrR736@users.github.com>
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

#ifndef __PLATFORMS_H__
#define __PLATFORMS_H__

#include <stdint.h>
#include <stddef.h> // for size_t

// -----------------------------------------------------------------------------
// Type-safe casting macros
// -----------------------------------------------------------------------------

#define hash_c_cast(t,p)	((t)(intptr_t)(p))
#define uhash_c_cast(t,p)	((t)(uintptr_t)(p))

#ifdef __cplusplus
#define hash_cast(t,p) static_cast<t>(p)
#define uhash_cast(t,p) reinterpret_cast<t>(p)
#else
#define hash_cast hash_c_cast
#define uhash_cast uhash_c_cast
#endif

// -----------------------------------------------------------------------------
// Configurable custom memset/memcpy
// -----------------------------------------------------------------------------

// User can define HASH_USE_CUSTOM_MEM before including this header
#ifndef HASH_USE_CUSTOM_MEM
# if (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)) || \
	(!defined(__WINDOWS__) && (defined(WIN32) || defined(WIN64) || defined(_MSC_VER) || defined(_WIN32)))
#  define HASH_USE_CUSTOM_MEM 0
# else
#  define HASH_USE_CUSTOM_MEM 1
# endif
#endif

#if HASH_USE_CUSTOM_MEM

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

static void* libhash_memset(void* s, int c, size_t n) {
	unsigned char* p = uhash_cast(unsigned char*, s);
	unsigned char val = hash_cast(unsigned char, c);
#if defined(__GNUC__) || defined(__clang__)
	for (size_t i = 0; i < n; ++i) { p[i] = val; }
#else
	while (n--) { *p++ = val; }
#endif
	return s;
}

static void* libhash_memcpy(void* dest, const void* src, size_t n) {
	unsigned char* d = uhash_cast(unsigned char*, dest);
	const unsigned char* s = uhash_cast(const unsigned char*, src);
	for (size_t i = 0; i < n; ++i) { d[i] = s[i]; }
	return dest;
}

static size_t libhash_strlen(const char *s) {
	if (s == NULL) { return 0; }
	const char *p = s;
	while (*p) { ++p; }
	return hash_cast(size_t,p - s);
}

/**
 * Convert an ASCII character to lowercase.
 * Non-alphabetic characters are unchanged.
 */
static int libhash_tolower(int c) {
	if (c >= 'A' && c <= 'Z') return c + ('a' - 'A');
	return c;
}

/**
 * Convert an ASCII character to uppercase.
 * Non-alphabetic characters are unchanged.
 */
static int libhash_toupper(int c) {
	if (c >= 'a' && c <= 'z') return c - ('a' - 'A');
	return c;
}

static int libhash_isalpha(int c) {
	return (c >= 'A' && c <= 'Z') ||
		   (c >= 'a' && c <= 'z');
}

static int libhash_isspace(int c) {
	return c == ' '  || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r';
}

static void *libhash_realloc(void *ptr, size_t size) {
	void *out = malloc(size);
	if (out == NULL) {
		free(ptr);
		return NULL;
	}
	libhash_memcpy(out,ptr, size);
	return out;
}

static void *libhash_calloc(size_t nmemb, size_t size) {
	if (nmemb != 0 && size > SIZE_MAX / nmemb) return NULL;
	size_t total = nmemb * size;
	void *ptr = malloc(total);
	if (ptr == NULL) return NULL;
	libhash_memset(ptr, 0, total);
	return ptr;
}

#ifdef __cplusplus
} // extern "C"
#endif

// Override standard functions
#define memset  libhash_memset
#define memcpy  libhash_memcpy
#define strlen  libhash_strlen
#define tolower libhash_tolower
#define toupper libhash_toupper
#define isalpha libhash_isalpha
#define isspace libhash_isspace
#define realloc libhash_realloc
#define calloc  libhash_calloc

#else // HASH_USE_CUSTOM_MEM not enabled

#include <ctype.h>
#ifdef _WIN32
#include <string.h>
#else
#include <memory.h>
#endif

#endif // HASH_USE_CUSTOM_MEM

#endif // __PLATFORMS_H__
