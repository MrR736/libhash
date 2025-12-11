/**
 * WjCryptLib_base32
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

#ifndef __BASE32_H__
#define __BASE32_H__

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

#define BASE32_SUCCESS 0
#define BASE32_ERR_INVALID_ARG  -1
#define BASE32_ERR_ALLOC_FAIL   -2
#define BASE32_ERR_BAD_CHAR     -3

typedef struct {
    const char *alphabet;  // 32-character alphabet
    char pad;              // padding character ('=' or 0 for none)
    int case_insensitive;  // 1 to decode in case-insensitive mode
} base32_config_t;

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- Encode ---------- */
LIBHASH_INLINE_API char *base32_encode_custom(const void *data, size_t len, const base32_config_t *cfg) {
    if (!data || !cfg || !cfg->alphabet) return NULL;
    if (strlen(cfg->alphabet) != 32) return NULL;

    size_t out_unpadded = (len * 8 + 4) / 5;
    size_t out_len = out_unpadded;
    if (cfg->pad) out_len = ((out_unpadded + 7) / 8) * 8;

    char *out = malloc(out_len + 1);
    if (!out) return NULL;

    uint32_t buffer = 0;
    int bits = 0;
    size_t out_pos = 0;

    for (size_t i = 0; i < len; ++i) {
	buffer = (buffer << 8) | uhash_cast(uint8_t*,data)[i];
	bits += 8;
	while (bits >= 5) {
	    bits -= 5;
	    uint8_t index = (buffer >> bits) & 0x1F;
	    out[out_pos++] = cfg->alphabet[index];
	}
    }
    if (bits > 0) {
	uint8_t index = (buffer << (5 - bits)) & 0x1F;
	out[out_pos++] = cfg->alphabet[index];
    }

    if (cfg->pad) while (out_pos % 8 != 0) out[out_pos++] = cfg->pad;
    out[out_pos] = '\0';
    return out;
}

/* ---------- Decode ---------- */
LIBHASH_INLINE_API int base32_decode_custom(const char *str, const base32_config_t *cfg, void **out, size_t *out_len) {
    // 1. Check for invalid arguments
    if (!str || !cfg || !cfg->alphabet || !out || !out_len)
        return BASE32_ERR_INVALID_ARG;

    // 2. Ensure the custom alphabet is exactly 32 characters long
    if (strlen(cfg->alphabet) != 32)
        return BASE32_ERR_INVALID_ARG;

    // 3. Calculate the required size for the output buffer based on the input length
    size_t slen = strlen(str);
    *out = malloc((slen * 5 + 7) / 8);  // Reserve space for the decoded data
    if (!*out)
        return BASE32_ERR_ALLOC_FAIL;  // Memory allocation failed

    // 4. Initialize a map to convert each character in the alphabet to its index (Base32 value)
    int map[256];  // 256 possible characters (byte size)
    for (int i = 0; i < 256; ++i)
        map[i] = -1;  // Initialize map with invalid values (-1)

    // 5. Populate the map with values from the custom alphabet
    for (int i = 0; i < 32; ++i) {
        unsigned char c = hash_cast(unsigned char, cfg->alphabet[i]);
        map[c] = i;  // Map character to its Base32 value

        if (cfg->case_insensitive) {
            map[tolower(c)] = i;  // Map lowercase versions as well
            map[toupper(c)] = i;  // Map uppercase versions as well
        }
    }

    // 6. Prepare variables for decoding
    uint32_t buffer = 0;  // Buffer to accumulate bits
    int bits = 0;         // Number of bits in the buffer
    size_t out_pos = 0;   // Position in the output buffer

    // 7. Decode the input string
    for (size_t i = 0; i < slen; ++i) {
        unsigned char c = hash_cast(unsigned char, str[i]);

        if (isspace(c)) continue;  // Ignore whitespace characters

        // Stop decoding if padding character is encountered
        if (cfg->pad && c == cfg->pad) break;

        // Get the Base32 value for the current character
        int val = map[c];
        if (val < 0) {
            free(*out);  // Invalid character encountered, free the output buffer
            return BASE32_ERR_BAD_CHAR;  // Return error
        }

        // Add the Base32 value to the buffer
        buffer = (buffer << 5) | val;
        bits += 5;

        // If we have at least 8 bits, write them to the output buffer
        if (bits >= 8) {
            bits -= 8;
            uhash_cast(uint8_t*, *out)[out_pos++] = (buffer >> bits) & 0xFF;
        }
    }

    // 8. Resize the output buffer to the exact decoded size
    *out = realloc(*out, out_pos);  // Reallocate to fit the decoded data
    *out_len = out_pos;             // Set the decoded data length
    return BASE32_SUCCESS;          // Success
}


LIBHASH_INLINE_API char *base32_encode(const void *data, size_t len) {
    if (!data) return NULL;
    if (len == 0) {
	char *out = (char*)malloc(1);
	if (out) out[0] = '\0';
	return out;
    }
    base32_config_t cfg = {"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",'=',0};
    return base32_encode_custom(data,len,&cfg);
}

LIBHASH_INLINE_API int base32_decode(const char *str, void **out, size_t *out_len) {
    if (!str || !out || !out_len) return BASE32_ERR_INVALID_ARG;
    size_t slen = strlen(str);
    if (slen == 0) { *out = NULL; *out_len = 0; return BASE32_SUCCESS; }
    base32_config_t cfg = {"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",'=',0};
    return base32_decode_custom(str,&cfg,out,out_len);
}

// ---------- Encoder ----------
LIBHASH_INLINE_API char *base32hex_encode(const void *data, size_t len) {
    if (!data) return NULL;
    if (len == 0) {
	char *out = (char*)malloc(1);
	if (out) out[0] = '\0';
	return out;
    }
    base32_config_t cfg = {"0123456789ABCDEFGHIJKLMNOPQRSTUV",'=',1};
    return base32_encode_custom(data,len,&cfg);
}

// ---------- Decoder ----------
LIBHASH_INLINE_API int base32hex_decode(const char *str, void **out, size_t *out_len) {
    if (!str || !out || !out_len) return BASE32_ERR_INVALID_ARG;
    size_t slen = strlen(str);
    if (slen == 0) { *out = NULL; *out_len = 0; return BASE32_SUCCESS; }
    base32_config_t cfg = {"0123456789ABCDEFGHIJKLMNOPQRSTUV",'=',1};
    return base32_decode_custom(str,&cfg,out,out_len);
}

// ---------- Encoder ----------
LIBHASH_INLINE_API char *zbase32_encode(const void *data, size_t len) {
    if (!data) return NULL;
    if (len == 0) {
	char *out = (char*)malloc(1);
	if (out) out[0] = '\0';
	return out;
    }
    base32_config_t cfg = {"ybndrfg8ejkmcpqxot1uwisza345h769",0,1};
    return base32_encode_custom(data,len,&cfg);
}

// ---------- Decoder ----------
LIBHASH_INLINE_API int zbase32_decode(const char *str, void **out, size_t *out_len) {
    if (!str || !out || !out_len) return BASE32_ERR_INVALID_ARG;
    size_t slen = strlen(str);
    if (slen == 0) { *out = NULL; *out_len = 0; return BASE32_SUCCESS; }
    base32_config_t cfg = {"ybndrfg8ejkmcpqxot1uwisza345h769",0,1};
    return base32_decode_custom(str,&cfg,out,out_len);
}

/* ---------------- Encoder ---------------- */
LIBHASH_INLINE_API char *crockford_base32_encode(const void *data, size_t len) {
    if (!data) return NULL;
    if (len == 0) {
        char *out = (char*)malloc(1);
        if (out) out[0] = '\0';
        return out;
    }
    base32_config_t cfg = {"0123456789ABCDEFGHJKMNPQRSTVWXYZ", 0, 0};
    return base32_encode_custom(data, len, &cfg);
}

/* ---------------- Decoder ---------------- */
LIBHASH_INLINE_API int crockford_base32_decode(const char *str, void **out, size_t *out_len) {
    if (!str || !out || !out_len) return BASE32_ERR_INVALID_ARG;
    size_t slen = strlen(str);
    if (slen == 0) { *out = NULL; *out_len = 0; return BASE32_SUCCESS; }

    base32_config_t cfg= {"0123456789ABCDEFGHJKMNPQRSTVWXYZ",0,1};

    size_t normalized_len = 0;
    char *normalized = (char*)malloc(slen + 1);
    if (!normalized) return BASE32_ERR_ALLOC_FAIL;
    for (size_t i = 0; i < slen; ++i) {
	char c = str[i];
	if (isspace(hash_cast(unsigned char,c))) continue;
	switch (c) {
	    case 'o': case 'O':
	    case 'u': case 'U':
		c = '0'; break;
	    case 'i': case 'I':
	    case 'l': case 'L':
		c = '1'; break;
	    default:
		c = toupper(hash_cast(unsigned char,c));
		break;
	}
	normalized[normalized_len++] = c;
    }
    normalized[normalized_len] = '\0';
    int result = base32_decode_custom(normalized, &cfg, out, out_len);
    free(normalized);
    return result;
}

#ifdef __cplusplus
}
#endif

#endif /* __BASE32_H__ */
