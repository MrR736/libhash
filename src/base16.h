/**
 * WjCryptLib_base16
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

#ifndef __BASE16_H__
#define __BASE16_H__

#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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
#if defined(WIN32) || defined(WIN64) || defined(_WIN32) || defined(_WIN64)
#define LIBHASH_EXPORT __declspec(dllexport) LIBHASH_VISIBILITY(default)
#else
#define LIBHASH_EXPORT LIBHASH_VISIBILITY(default)
#endif
#endif

#ifndef LIBHASH_IMPORT
#if defined(WIN32) || defined(WIN64) || defined(_WIN32) || defined(_WIN64)
#define LIBHASH_IMPORT __declspec(dllimport) LIBHASH_VISIBILITY(default)
#else
#define LIBHASH_IMPORT LIBHASH_VISIBILITY(default)
#endif
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

#define BASE16_SUCCESS		 0
#define BASE16_ERR_INVALID_ARG	-1
#define BASE16_ERR_ALLOC_FAIL	-2
#define BASE16_ERR_BAD_CHAR	-3

typedef struct {
	const char *alphabet;
	int case_insensitive;
} base16_config_t;

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- Encode ---------- */
LIBHASH_INLINE_API char *base16_encode_custom(const void *data, size_t len, const base16_config_t *cfg) {
	if (!data || !cfg || !cfg->alphabet)
		return NULL;

	const unsigned char *bytes = (const unsigned char*)data;
	const char *alphabet = cfg->alphabet;

	/* Allocate 2× input size + null terminator */
	char *out = (char*)malloc(len * 2 + 1);
	if (!out)
		return NULL;

	size_t idx = 0;
	for (size_t i = 0; i < len; i++) {
		unsigned char b = bytes[i];
		out[idx++] = alphabet[(b >> 4) & 0x0F];
		out[idx++] = alphabet[b & 0x0F];
	}

	out[idx] = '\0';
	return out;
}


/* ---------- Decode ---------- */
LIBHASH_INLINE_API int base16_decode_custom(const char *str, const base16_config_t *cfg,void **out, size_t *out_len) {
	if (!str || !cfg || !cfg->alphabet || !out || !out_len)
		return BASE16_ERR_INVALID_ARG;

	size_t slen = strlen(str);

	/* Hex must have even length */
	if (slen % 2 != 0)
		return BASE16_ERR_BAD_CHAR;

	/* Build table: char → value */
	int map[256];
	for (int i = 0; i < 256; i++)
		map[i] = -1;

	for (int i = 0; cfg->alphabet[i]; i++) {
		unsigned char c = hash_cast(unsigned char,cfg->alphabet[i]);
		map[c] = i;

		if (cfg->case_insensitive && isalpha(c)) {
			map[hash_cast(unsigned char,toupper(c))] = i;
			map[hash_cast(unsigned char,tolower(c))] = i;
		}
	}

	size_t out_n = slen / 2;
	unsigned char *buf = (unsigned char*)malloc(out_n);
	if (!buf)
		return BASE16_ERR_ALLOC_FAIL;

	/* Decode hex pairs */
	for (size_t i = 0; i < out_n; i++) {
		unsigned char c1 = hash_cast(unsigned char,str[i * 2]);
		unsigned char c2 = hash_cast(unsigned char,str[i * 2 + 1]);

		int v1 = map[c1];
		int v2 = map[c2];

		if (v1 < 0 || v2 < 0) {
			free(buf);
			return BASE16_ERR_BAD_CHAR;
		}

		buf[i] = hash_cast(unsigned char, ((v1 << 4) | v2));
	}

	*out = buf;
	*out_len = out_n;
	return BASE16_SUCCESS;
}

LIBHASH_INLINE_API char *base16_encode(const void *data, size_t len, int uppercase) {
	if (!data) return NULL;
	if (len == 0) {
		char *out = (char*)malloc(1);
		if (out) out[0] = '\0';
		return out;
	}
	const char *alphabet = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
	base16_config_t cfg = {alphabet,0};
	return base16_encode_custom(data,len,&cfg);
}

LIBHASH_INLINE_API int base16_decode(const char *str, void **out, size_t *out_len, int uppercase) {
	if (!str || !out || !out_len) return BASE16_ERR_INVALID_ARG;
	size_t slen = strlen(str);
	if (slen == 0) { *out = NULL; *out_len = 0; return BASE16_SUCCESS; }
	const char *alphabet = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
	base16_config_t cfg = {alphabet,0};
	return base16_decode_custom(str,&cfg,out,out_len);
}

#ifdef __cplusplus
}
#endif

#endif /* __BASE16_H__ */
