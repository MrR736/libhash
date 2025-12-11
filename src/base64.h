/**
 * WjCryptLib_base64
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

#ifndef __BASE64_H__
#define __BASE64_H__

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

#define BASE64_SUCCESS		 0
#define BASE64_ERR_INVALID_ARG	-1
#define BASE64_ERR_ALLOC_FAIL	-2
#define BASE64_ERR_BAD_CHAR	-3

typedef struct {
	const char *alphabet;
	char pad;
	int case_insensitive;
} base64_config_t;

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- Encode ---------- */
LIBHASH_INLINE_API char *base64_encode_custom(const void *data, size_t len, const base64_config_t *cfg) {
	if (!data || !cfg || !cfg->alphabet) return NULL;
	if (strlen(cfg->alphabet) != 64) return NULL;

	size_t out_len = ((len + 2) / 3) * 4;
	char *out = (char*)malloc(out_len + 1);
	if (!out) return NULL;

	const uint8_t *in = uhash_cast(const uint8_t*,data);
	size_t out_pos = 0;

	for (size_t i = 0; i < len; i += 3) {
		uint32_t triple = ((uint32_t)in[i]) << 16;
		int rem = (int)(len - i);

		if (rem > 1) triple |= ((uint32_t)in[i + 1]) << 8;
		if (rem > 2) triple |= ((uint32_t)in[i + 2]);

		out[out_pos++] = cfg->alphabet[(triple >> 18) & 0x3F];
		out[out_pos++] = cfg->alphabet[(triple >> 12) & 0x3F];

		if (rem > 1)
			out[out_pos++] = cfg->alphabet[(triple >> 6) & 0x3F];
		else if (cfg->pad)
			out[out_pos++] = cfg->pad;

		if (rem > 2)
			out[out_pos++] = cfg->alphabet[triple & 0x3F];
		else if (cfg->pad)
			out[out_pos++] = cfg->pad;
	}

	// Trim any '\0' if no padding
	if (!cfg->pad) {
		out[out_pos] = '\0';
		char *tmp = realloc(out, out_pos + 1);
		return tmp ? tmp : out;
	}

	out[out_len] = '\0';
	return out;
}

/* ---------- Decode ---------- */
LIBHASH_INLINE_API int base64_decode_custom(const char *str, const base64_config_t *cfg, void **out, size_t *out_len) {
	if (!str || !cfg || !cfg->alphabet || !out || !out_len)
		return BASE64_ERR_INVALID_ARG;
	if (strlen(cfg->alphabet) != 64)
		return BASE64_ERR_INVALID_ARG;

	size_t slen = strlen(str);
	if (slen == 0) {
		*out = NULL;
		*out_len = 0;
		return BASE64_SUCCESS;
	}

	/* Build decode map */
	int map[256];
	for (int i = 0; i < 256; ++i) map[i] = -1;

	for (int i = 0; i < 64; ++i) {
		uint8_t c = hash_cast(uint8_t, cfg->alphabet[i]);
		map[c] = i;

		if (cfg->case_insensitive && isalpha(c)) {
			uint8_t lc = (uint8_t)tolower(c);
			uint8_t uc = (uint8_t)toupper(c);
			if (map[lc] < 0) map[lc] = i;
			if (map[uc] < 0) map[uc] = i;
		}
	}

	uint8_t *dst = malloc((slen * 3) / 4 + 3);
	if (!dst) return BASE64_ERR_ALLOC_FAIL;

	size_t out_pos = 0;
	uint32_t buf = 0;
	int val_count = 0;

	for (size_t i = 0; i < slen; ++i) {
		uint8_t c = hash_cast(uint8_t, str[i]);

		if (isspace(c)) continue;

		if (cfg->pad && c == cfg->pad) {
			/* verify remaining chars are pad/space */
			for (size_t j = i; j < slen; j++) {
				uint8_t d = str[j];
				if (d != cfg->pad && !isspace(d)) {
					free(dst);
					return BASE64_ERR_BAD_CHAR;
				}
			}
			break;
		}

		int val = map[c];
		if (val < 0) {
			free(dst);
			return BASE64_ERR_BAD_CHAR;
		}

		buf = (buf << 6) | val;
		val_count++;

		if (val_count == 4) {
			dst[out_pos++] = (buf >> 16) & 0xFF;
			dst[out_pos++] = (buf >> 8)  & 0xFF;
			dst[out_pos++] =  buf        & 0xFF;
			buf = 0;
			val_count = 0;
		}
	}

	/* Flush remaining sextets */
	if (val_count == 1) {
		/* Impossible in valid Base64 */
		free(dst);
		return BASE64_ERR_BAD_CHAR;
	}
	else if (val_count == 2) {
		/* final 8 bits */
		dst[out_pos++] = (buf >> 4) & 0xFF;
	}
	else if (val_count == 3) {
		dst[out_pos++] = (buf >> 10) & 0xFF;
		dst[out_pos++] = (buf >> 2)  & 0xFF;
	}

	/* shrink buffer */
	uint8_t *tmp = realloc(dst, out_pos ? out_pos : 1);
	if (!tmp) {
		free(dst);
		return BASE64_ERR_ALLOC_FAIL;
	}
	dst = tmp;

	*out = dst;
	*out_len = out_pos;
	return BASE64_SUCCESS;
}

/* ---------- Convenience Wrappers ---------- */
LIBHASH_INLINE_API char *base64_encode(const void *data, size_t len) {
	base64_config_t cfg = { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", '=', 0 };
	return base64_encode_custom(data, len, &cfg);
}

LIBHASH_INLINE_API int base64_decode(const char *str, void **out, size_t *out_len) {
	base64_config_t cfg = { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", '=', 0 };
	return base64_decode_custom(str, &cfg, out, out_len);
}

/* ---------- URL-safe variant ---------- */
LIBHASH_INLINE_API char *base64url_encode(const void *data, size_t len) {
	base64_config_t cfg = { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", '\0', 0 };
	return base64_encode_custom(data, len, &cfg);
}

LIBHASH_INLINE_API int base64url_decode(const char *str, void **out, size_t *out_len) {
	base64_config_t cfg = { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", '\0', 0 };
	return base64_decode_custom(str, &cfg, out, out_len);
}

/* ---------- MIME (RFC 2045) variant ---------- */
LIBHASH_INLINE_API char *base64mime_encode(const void *data, size_t len) {
	base64_config_t cfg = { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", '=', 0 };

	// Encode using the base routine
	char *raw = base64_encode_custom(data, len, &cfg);
	if (!raw) return NULL;

	size_t raw_len = strlen(raw);
	size_t lines = (raw_len + 75) / 76;
	size_t out_len = raw_len + (lines - 1) * 2; // CRLF every 76 chars

	char *out = (char*)malloc(out_len + 1);
	if (!out) {
		free(raw);
		return NULL;
	}

	size_t in_pos = 0, out_pos = 0;
	for (size_t line = 0; line < lines; ++line) {
		size_t chunk = (raw_len - in_pos >= 76) ? 76 : raw_len - in_pos;
		memcpy(out + out_pos, raw + in_pos, chunk);
		in_pos += chunk;
		out_pos += chunk;

		if (in_pos < raw_len) {
			out[out_pos++] = '\r';
			out[out_pos++] = '\n';
		}
	}

	out[out_pos] = '\0';
	free(raw);
	return out;
}

LIBHASH_INLINE_API int base64mime_decode(const char *str, void **out, size_t *out_len) {
	base64_config_t cfg = { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", '=', 0};
	return base64_decode_custom(str, &cfg, out, out_len);
}

#ifdef __cplusplus
}
#endif

#endif /* __BASE64_H__ */
