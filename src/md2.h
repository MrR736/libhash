/**
 * WjCryptLib_Md2
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

#ifndef __MD2_H__
#define __MD2_H__

#include <stdint.h>
#include <memory.h>

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

#define MD2_HASH_SIZE        16
#define MD2_BLOCK_SIZE       16
#define MD2_DIGEST_LENGTH    MD2_HASH_SIZE

typedef struct {
    uint8_t state[48];
    uint8_t checksum[16];
    uint8_t buffer[MD2_BLOCK_SIZE];
    uint32_t count;
} Md2Context;

typedef struct {
    uint8_t bytes[MD2_HASH_SIZE];
} MD2_HASH;

#ifdef __cplusplus
extern "C" {
#endif

static const uint8_t MD2_S[256] = {
    41,46,67,201,162,216,124,1,61,54,84,161,236,240,6,19,
    98,167,5,243,192,199,115,140,152,147,43,217,188,76,130,202,
    30,155,87,60,253,212,224,22,103,66,111,24,138,23,229,18,
    190,78,196,214,218,158,222,73,160,251,245,142,187,47,238,122,
    169,104,121,145,21,178,7,63,148,194,16,137,11,34,95,33,
    128,127,93,154,90,144,50,39,53,62,204,231,191,247,151,3,
    255,25,48,179,72,165,181,209,215,94,146,42,172,86,170,198,
    79,184,56,210,150,164,125,182,118,252,107,226,156,116,4,241,
    69,157,112,89,100,113,135,32,134,91,207,101,230,45,168,2,
    27,96,37,173,174,176,185,246,28,70,97,105,52,64,126,15,
    85,71,163,35,221,81,175,58,195,92,249,206,186,197,234,38,
    44,83,13,110,133,40,132,9,211,223,205,244,65,129,77,82,
    106,220,55,200,108,193,171,250,36,225,123,8,12,189,177,74,
    120,136,149,139,227,99,232,109,233,203,213,254,59,0,29,57,
    242,239,183,14,102,88,208,228,166,119,114,248,235,117,75,10,
    49,68,80,180,143,237,31,26,219,153,141,51,159,17,131,20
};

static inline void Md2ProcessBlock(Md2Context *ctx, const uint8_t* block) {
    uint8_t t = 0;
    uint8_t X[48];

    // 1. Copy state and block
    memcpy(X, ctx->state, 16);
    memcpy(X + 16, block, 16);
    for (int i = 0; i < 16; ++i)
	X[32 + i] = X[i] ^ X[16 + i];

    // 2. 18 rounds of nonlinear mixing
    for (int j = 0; j < 18; ++j) {
	for (int k = 0; k < 48; ++k)
	    t = X[k] ^= MD2_S[t];
	t = (t + j) & 0xFF;
    }

    // 3. Store new state
    memcpy(ctx->state, X, 48);
    uint8_t L = ctx->checksum[15];
    for (int i = 0; i < 16; ++i) {
	ctx->checksum[i] ^= MD2_S[block[i] ^ L];
	L = ctx->checksum[i];
    }
}

LIBHASH_INLINE_API void Md2Initialise(Md2Context *ctx) {
    memset(ctx, 0, sizeof(*ctx));
}

LIBHASH_INLINE_API void Md2Update(Md2Context *ctx, const void *data, uint32_t len) {
    const uint8_t *input = (const uint8_t *)data;
    uint32_t have = ctx->count;

    if (have) {
	uint32_t need = MD2_BLOCK_SIZE - have;
	if (len < need) {
	    memcpy(ctx->buffer + have, input, len);
	    ctx->count += len;
	    return;
	}
	memcpy(ctx->buffer + have, input, need);
	Md2ProcessBlock(ctx, ctx->buffer);
	input += need;
	len -= need;
	ctx->count = 0;
    }

    while (len >= MD2_BLOCK_SIZE) {
	Md2ProcessBlock(ctx, input);
	input += MD2_BLOCK_SIZE;
	len -= MD2_BLOCK_SIZE;
    }

    if (len > 0) {
	memcpy(ctx->buffer, input, len);
	ctx->count = len;
    }
}

LIBHASH_INLINE_API void Md2Finalise(Md2Context *ctx, MD2_HASH *digest) {
    uint8_t padLen = (uint8_t)(MD2_BLOCK_SIZE - ctx->count);
    uint8_t pad[MD2_BLOCK_SIZE];
    for (int i = 0; i < padLen; ++i)
	pad[i] = padLen;
    Md2Update(ctx, pad, padLen);
    // Process checksum as final block per RFC 1319
    Md2ProcessBlock(ctx, ctx->checksum);
    memcpy(digest->bytes, ctx->state, 16);
    memset(ctx, 0, sizeof(*ctx));
}

LIBHASH_INLINE_API void Md2Calculate(const void *data, uint32_t len, MD2_HASH *digest) {
    Md2Context ctx;
    Md2Initialise(&ctx);
    Md2Update(&ctx, data, len);
    Md2Finalise(&ctx, digest);
}

#ifdef __cplusplus
}
#endif

#endif /* __MD2_H__ */
