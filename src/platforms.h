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

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnonnull-compare"
#endif

#ifdef __cplusplus
extern "C" {
#endif

static void* libhash_memset(void* __s, int __c, size_t __n) {
	unsigned char* p = uhash_cast(unsigned char*, __s);
	unsigned char val = hash_cast(unsigned char, __c);

#if defined(__GNUC__) || defined(__clang__)
	for (size_t i = 0; i < __n; ++i) {
		p[i] = val;
	}
#else
	while (__n--) {
		*p++ = val;
	}
#endif
	return __s;
}

static void* libhash_memcpy(void* __dest, const void* __src, size_t __n) {
	unsigned char* d = uhash_cast(unsigned char*, __dest);
	const unsigned char* s = uhash_cast(const unsigned char*, __src);

#if defined(__GNUC__) || defined(__clang__)
	for (size_t i = 0; i < __n; ++i) {
		d[i] = s[i];
	}
#else
	while (__n--) {
		*d++ = *s++;
	}
#endif
	return __dest;
}

static unsigned long libhash_strlen(const char *__s) {
	if (__s == NULL) {
		return 0;
	}
	const char *p = __s;
	while (*p) {
		++p;
	}
	return hash_cast(unsigned long,p - __s);
}

/**
 * Convert an ASCII character to lowercase.
 * Non-alphabetic characters are unchanged.
 */
static int libhash_tolower(int __c) {
	if (__c >= 'A' && __c <= 'Z') {
		return __c + ('a' - 'A');
	}
	return __c;
}

/**
 * Convert an ASCII character to uppercase.
 * Non-alphabetic characters are unchanged.
 */
static int libhash_toupper(int __c) {
	if (__c >= 'a' && __c <= 'z') {
		return __c - ('a' - 'A');
	}
	return __c;
}

#ifdef __cplusplus
} // extern "C"
#endif

// Override standard functions
#define memset libhash_memset
#define memcpy libhash_memcpy
#define strlen libhash_strlen
#define tolower libhash_tolower
#define toupper libhash_toupper

#else // HASH_USE_CUSTOM_MEM not enabled

#include <ctype.h>
#include <string.h>

#endif // HASH_USE_CUSTOM_MEM

#endif // __PLATFORMS_H__
