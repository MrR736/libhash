/**
 * WjCryptLib_base8
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

#ifndef __BASE8_H__
#define __BASE8_H__

#include <stdint.h>
#include <stdlib.h>

#if !HASH_USE_CUSTOM_MEM
# include <ctype.h>
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
#if (defined(__GNUC__) && (__GNUC__ >= 4) && (__GNUC_MINOR__ > 2)) || __has_attribute(visibility)
#define LIBHASH_VISIBILITY(V) __attribute__((visibility (#V)))
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

#define hash_c_cast(t,p)    ((t)(intptr_t)(p))
#define uhash_c_cast(t,p)   ((t)(uintptr_t)(p))

#ifdef __cplusplus
#define hash_cast(t,p) static_cast<t>(p)
#define uhash_cast(t,p) reinterpret_cast<t>(p)
#else
#define hash_cast hash_c_cast
#define uhash_cast uhash_c_cast
#endif

#define BASE8_SUCCESS           0
#define BASE8_ERR_INVALID_ARG  -1
#define BASE8_ERR_ALLOC_FAIL   -2
#define BASE8_ERR_BAD_CHAR     -3

typedef struct {
	const char *alphabet;
	int case_insensitive;
} base8_config_t;

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- Encode ---------- */

LIBHASH_INLINE_API char *base8_encode_custom(const void *data,size_t len,const base8_config_t *cfg) {
	if (!data || !cfg || !cfg->alphabet) return NULL;
	const unsigned char *bytes = (const unsigned char *)data;
	const char *alphabet = cfg->alphabet;
	/*
	 * Each byte requires three octal digits:
	 *
	 *   000 - 377
	 */
	char *out = (char *)malloc(len * 3 + 1);
	if (!out) return NULL;
	size_t idx = 0;
	for (size_t i = 0; i < len; i++) {
		unsigned char b = bytes[i];
		out[idx++] = alphabet[(b >> 6) & 0x03];
		out[idx++] = alphabet[(b >> 3) & 0x07];
		out[idx++] = alphabet[b & 0x07];
	}
	out[idx] = '\0';
	return out;
}


/* ---------- Decode ---------- */

LIBHASH_INLINE_API int base8_decode_custom(const char *str,const base8_config_t *cfg,void **out,size_t *out_len) {
	if (!str || !cfg || !cfg->alphabet || !out || !out_len) return BASE8_ERR_INVALID_ARG;
	size_t slen = strlen(str);

	/*
	 * Each byte is represented by exactly three octal digits.
	 */
	if (slen % 3 != 0) return BASE8_ERR_BAD_CHAR;
	int map[256];
	for (int i = 0; i < 256; i++) map[i] = -1;

	// Build character -> octal value table.
	for (int i = 0; cfg->alphabet[i]; i++) {
		unsigned char c = hash_cast(unsigned char, cfg->alphabet[i]);
		// Base8 only requires eight symbols.
		if (i >= 8) break;
		map[c] = i;
		if (cfg->case_insensitive && isalpha(c)) {
			map[hash_cast(unsigned char, toupper(c))] = i;
			map[hash_cast(unsigned char, tolower(c))] = i;
		}
	}

	size_t out_n = slen / 3;
	unsigned char *buf = (unsigned char *)malloc(out_n);
	if (!buf && out_n != 0) return BASE8_ERR_ALLOC_FAIL;

	// Decode groups of three octal digits.
	for (size_t i = 0; i < out_n; i++) {
		unsigned char c1 = hash_cast(unsigned char, str[i * 3]);
		unsigned char c2 = hash_cast(unsigned char, str[i * 3 + 1]);
		unsigned char c3 = hash_cast(unsigned char, str[i * 3 + 2]);
		int v1 = map[c1];
		int v2 = map[c2];
		int v3 = map[c3];
		if (v1 < 0 || v2 < 0 || v3 < 0 || v1 > 3 || v2 > 7 || v3 > 7) {
			free(buf);
			return BASE8_ERR_BAD_CHAR;
		}
		buf[i] = hash_cast(unsigned char,(v1 << 6) | (v2 << 3) | v3);
	}
	*out = buf;
	*out_len = out_n;
	return BASE8_SUCCESS;
}


/* ---------- Standard Base8 ---------- */
LIBHASH_INLINE_API char *base8_encode(const void *data,size_t len) {
	base8_config_t cfg = {"01234567",0};
	return base8_encode_custom(data, len, &cfg);
}

LIBHASH_INLINE_API int base8_decode(const char *str,void **out,size_t *out_len) {
	base8_config_t cfg = {"01234567",0};
	return base8_decode_custom(str,&cfg,out,out_len);
}


#ifdef __cplusplus
}
#endif

#endif /* __BASE8_H__ */
