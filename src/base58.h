/**
 * WjCryptLib_base58
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
 */

#ifndef __BASE58_H__
#define __BASE58_H__

#include <stdint.h>
#include <stddef.h>
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
#if (defined(__GNUC__) && (__GNUC__ >= 4) && (__GNUC_MINOR__ > 2)) || \
	(defined(__has_attribute) && __has_attribute(visibility))
#define LIBHASH_VISIBILITY(V) __attribute__((visibility(#V)))
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

#define hash_c_cast(t,p)	((t)(intptr_t)(p))
#define uhash_c_cast(t,p)	((t)(uintptr_t)(p))

#ifdef __cplusplus
#define hash_cast(t,p) static_cast<t>(p)
#define uhash_cast(t,p) reinterpret_cast<t>(p)
#else
#define hash_cast hash_c_cast
#define uhash_cast uhash_c_cast
#endif

#define BASE58_SUCCESS			0
#define BASE58_ERR_INVALID_ARG	-1
#define BASE58_ERR_ALLOC_FAIL	-2
#define BASE58_ERR_BAD_CHAR		-3

typedef struct {
	const char *alphabet;
	int case_insensitive;
} base58_config_t;

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- Encode ---------- */
LIBHASH_INLINE_API char *base58_encode_custom(const void *data,size_t len,const base58_config_t *cfg) {
	if ((!data && len != 0) || !cfg || !cfg->alphabet) return NULL;
	if (strlen(cfg->alphabet) != 58) return NULL;
	if (len == 0) {
		char *out = (char *)malloc(1);
		if (out) out[0] = '\0';
		return out;
	}
	const uint8_t *input = uhash_cast(const uint8_t *, data);
	if (len > (SIZE_MAX - 2) / 138) return NULL;
	size_t max_len = (len * 138) / 100 + 2;
	uint8_t *digits = (uint8_t *)malloc(max_len);
	if (!digits) return NULL;
	size_t digits_len = 1;
	digits[0] = 0;
	for (size_t i = 0; i < len; ++i) {
		unsigned int carry = input[i];
		for (size_t j = 0; j < digits_len; ++j) {
			unsigned int value = (unsigned int)digits[j] * 256U + carry;
			digits[j] = (uint8_t)(value % 58U);
			carry = value / 58U;
		}
		while (carry != 0) {
			if (digits_len >= max_len) {
				free(digits);
				return NULL;
			}
			digits[digits_len++] = (uint8_t)(carry % 58U);
			carry /= 58U;
		}
	}
	size_t leading_zeroes = 0;
	while (leading_zeroes < len && input[leading_zeroes] == 0) ++leading_zeroes;
	size_t numeric_len = digits_len;
	if (numeric_len == 1 && digits[0] == 0) numeric_len = 0;
	if (leading_zeroes > SIZE_MAX - numeric_len - 1) {
		free(digits);
		return NULL;
	}
	size_t out_len = leading_zeroes + numeric_len;
	char *out = (char *)malloc(out_len + 1);
	if (!out) {
		free(digits);
		return NULL;
	}
	size_t pos = 0;
	for (size_t i = 0; i < leading_zeroes; ++i) out[pos++] = cfg->alphabet[0];
	for (size_t i = numeric_len; i > 0; --i) {
		out[pos++] = cfg->alphabet[digits[i - 1]];
	}
	out[pos] = '\0';
	free(digits);
	return out;
}

/* ---------- Decode ---------- */
LIBHASH_INLINE_API int base58_decode_custom(const char *str,const base58_config_t *cfg,void **out,size_t *out_len) {
	if (!str || !cfg || !cfg->alphabet || !out || !out_len) return BASE58_ERR_INVALID_ARG;

	if (strlen(cfg->alphabet) != 58) return BASE58_ERR_INVALID_ARG;
	*out = NULL;
	*out_len = 0;
	size_t slen = strlen(str);
	if (slen == 0) return BASE58_SUCCESS;
	int map[256];
	for (int i = 0; i < 256; ++i) map[i] = -1;
	for (int i = 0; i < 58; ++i) {
		uint8_t c = hash_cast(uint8_t, cfg->alphabet[i]);
		map[c] = i;
		if (cfg->case_insensitive &&isalpha(c)) {
			uint8_t lc = (uint8_t)tolower(c);
			uint8_t uc = (uint8_t)toupper(c);
			if (map[lc] < 0) map[lc] = i;
			if (map[uc] < 0) map[uc] = i;
		}
	}

	size_t leading_zeroes = 0;
	while (leading_zeroes < slen) {
		uint8_t c =hash_cast(uint8_t,str[leading_zeroes]);
		if (c != (uint8_t)cfg->alphabet[0]) break;
		++leading_zeroes;
	}
	uint8_t *bytes = (uint8_t *)malloc(slen + 1);
	if (!bytes) return BASE58_ERR_ALLOC_FAIL;
	size_t bytes_len = 1;
	bytes[0] = 0;
	for (size_t i = 0; i < slen; ++i) {
		uint8_t c = hash_cast(uint8_t, str[i]);
		int value = map[c];
		if (value < 0) {
			free(bytes);
			return BASE58_ERR_BAD_CHAR;
		}
		unsigned int carry = (unsigned int)value;
		for (size_t j = 0; j < bytes_len; ++j) {
			unsigned int v = (unsigned int)bytes[j] * 58U + carry;
			bytes[j] = (uint8_t)(v & 0xFFU);
			carry = v >> 8;
		}
		while (carry != 0) {
			if (bytes_len >= slen + 1) {
				free(bytes);
				return BASE58_ERR_ALLOC_FAIL;
			}
			bytes[bytes_len++] = (uint8_t)(carry & 0xFFU);
			carry >>= 8;
		}
	}

	size_t numeric_len = bytes_len;
	if (numeric_len == 1 &&bytes[0] == 0) numeric_len = 0;
	if (leading_zeroes > SIZE_MAX - numeric_len) {
		free(bytes);
		return BASE58_ERR_ALLOC_FAIL;
	}
	size_t result_len = leading_zeroes + numeric_len;
	uint8_t *result = (uint8_t *)malloc(result_len ? result_len : 1);
	if (!result) {
		free(bytes);
		return BASE58_ERR_ALLOC_FAIL;
	}
	memset(result,0,leading_zeroes);
	for (size_t i = 0; i < numeric_len; ++i) {
		result[leading_zeroes + i] = bytes[bytes_len - i - 1];
	}
	free(bytes);
	*out = result;
	*out_len = result_len;
	return BASE58_SUCCESS;
}


/* ---------- Bitcoin Base58 ---------- */
LIBHASH_INLINE_API char *base58_encode(const void *data,size_t len) {
	static const base58_config_t cfg = {"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",0};
	return base58_encode_custom(data,len,&cfg);
}

LIBHASH_INLINE_API int base58_decode(const char *str,void **out,size_t *out_len) {
	static const base58_config_t cfg = {"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",0};
	return base58_decode_custom(str,&cfg,out,out_len);
}


/* ---------- Base58Check-compatible alphabet ---------- */
LIBHASH_INLINE_API char *base58btc_encode(const void *data,size_t len) {
	return base58_encode(data, len);
}

LIBHASH_INLINE_API int base58btc_decode(const char *str,void **out,size_t *out_len) {
	return base58_decode(str, out, out_len);
}

/* ---------- Ripple (XRPL) Base58 ---------- */
LIBHASH_INLINE_API char *base58ripple_encode(const void *data,size_t len) {
	static const base58_config_t cfg = {"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz",0};
	return base58_encode_custom(data,len,&cfg);
}

LIBHASH_INLINE_API int base58ripple_decode(const char *str,void **out,size_t *out_len) {
	static const base58_config_t cfg = {"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz",0};
	return base58_decode_custom(str,&cfg,out,out_len);
}

/* ---------- Flickr Base58 ---------- */
LIBHASH_INLINE_API char *base58flickr_encode(const void *data,size_t len) {
	static const base58_config_t cfg = {"123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ",0};
	return base58_encode_custom(data,len,&cfg);
}

LIBHASH_INLINE_API int base58flickr_decode(const char *str,void **out,size_t *out_len) {
	static const base58_config_t cfg = {"123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ",0};
	return base58_decode_custom(str,&cfg,out,out_len);
}

#ifdef __cplusplus
}
#endif

#endif /* __BASE58_H__ */
