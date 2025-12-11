/**
 * WjCryptLib_Md4
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

#ifndef __MD4_H__
#define __MD4_H__

#include <stdint.h>
#include <memory.h>
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

#define MD4_HASH_SIZE        16
#define MD4_BLOCK_SIZE       64
#define MD4_DIGEST_LENGTH    MD4_HASH_SIZE

typedef struct {
    uint32_t lo;
    uint32_t hi;
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint8_t  buffer[MD4_BLOCK_SIZE];
} Md4Context;

typedef struct {
    uint8_t bytes[MD4_HASH_SIZE];
} MD4_HASH;

/*------------------------------------------------------------
 * Basic operations
 *-----------------------------------------------------------*/
#define F4(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define G4(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H4(x, y, z) ((x) ^ (y) ^ (z))
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define FF(a,b,c,d,k,s) a = ROTL32(a + F4(b,c,d) + X[k], s)
#define GG(a,b,c,d,k,s) a = ROTL32(a + G4(b,c,d) + X[k] + 0x5A827999U, s)
#define HH(a,b,c,d,k,s) a = ROTL32(a + H4(b,c,d) + X[k] + 0x6ED9EBA1U, s)

/*------------------------------------------------------------
 * Core transform
 *-----------------------------------------------------------*/
static inline void Md4Transform(uint32_t *state, const uint8_t *block) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t X[16];

    for (int i = 0; i < 16; ++i) {
	X[i] =	hash_cast(uint32_t,block[i * 4]) | (hash_cast(uint32_t,block[i * 4 + 1]) << 8) |
		(hash_cast(uint32_t,block[i * 4 + 2]) << 16) | (hash_cast(uint32_t,block[i * 4 + 3]) << 24);
    }
    /* Round 1 */
    FF(a,b,c,d, 0, 3);  FF(d,a,b,c, 1, 7);  FF(c,d,a,b, 2,11);  FF(b,c,d,a, 3,19);
    FF(a,b,c,d, 4, 3);  FF(d,a,b,c, 5, 7);  FF(c,d,a,b, 6,11);  FF(b,c,d,a, 7,19);
    FF(a,b,c,d, 8, 3);  FF(d,a,b,c, 9, 7);  FF(c,d,a,b,10,11);  FF(b,c,d,a,11,19);
    FF(a,b,c,d,12, 3);  FF(d,a,b,c,13, 7);  FF(c,d,a,b,14,11);  FF(b,c,d,a,15,19);
    /* Round 2 */
    GG(a,b,c,d, 0, 3);  GG(d,a,b,c, 4, 5);  GG(c,d,a,b, 8, 9);  GG(b,c,d,a,12,13);
    GG(a,b,c,d, 1, 3);  GG(d,a,b,c, 5, 5);  GG(c,d,a,b, 9, 9);  GG(b,c,d,a,13,13);
    GG(a,b,c,d, 2, 3);  GG(d,a,b,c, 6, 5);  GG(c,d,a,b,10, 9);  GG(b,c,d,a,14,13);
    GG(a,b,c,d, 3, 3);  GG(d,a,b,c, 7, 5);  GG(c,d,a,b,11, 9);  GG(b,c,d,a,15,13);
    /* Round 3 */
    HH(a,b,c,d, 0, 3);  HH(d,a,b,c, 8, 9);  HH(c,d,a,b, 4,11);  HH(b,c,d,a,12,15);
    HH(a,b,c,d, 2, 3);  HH(d,a,b,c,10, 9);  HH(c,d,a,b, 6,11);  HH(b,c,d,a,14,15);
    HH(a,b,c,d, 1, 3);  HH(d,a,b,c, 9, 9);  HH(c,d,a,b, 5,11);  HH(b,c,d,a,13,15);
    HH(a,b,c,d, 3, 3);  HH(d,a,b,c,11, 9);  HH(c,d,a,b, 7,11);  HH(b,c,d,a,15,15);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    memset(X, 0, sizeof(X));
}

/*------------------------------------------------------------
 * API functions
 *-----------------------------------------------------------*/
LIBHASH_INLINE_API void Md4Initialise(Md4Context *ctx) {
	ctx->lo = ctx->hi = 0;
	ctx->a = 0x67452301U;
	ctx->b = 0xEFCDAB89U;
	ctx->c = 0x98BADCFEU;
	ctx->d = 0x10325476U;
}

LIBHASH_INLINE_API void Md4Update(Md4Context *ctx, const void *data, uint32_t len) {
    uint32_t saved_lo = ctx->lo;
    if ((ctx->lo = (saved_lo + len) & 0x1FFFFFFFU) < saved_lo)
	ctx->hi++;
    ctx->hi += len >> 29;
    uint32_t used = saved_lo & 0x3F;
    const uint8_t *input = (const uint8_t *)data;
    if (used) {
	uint32_t free = 64 - used;
	if (len < free) {
	    memcpy(&ctx->buffer[used], input, len);
	    return;
	}
	memcpy(&ctx->buffer[used], input, free);
	uint32_t state[4] = { ctx->a, ctx->b, ctx->c, ctx->d };
	Md4Transform(state, ctx->buffer);
	ctx->a = state[0]; ctx->b = state[1]; ctx->c = state[2]; ctx->d = state[3];
	input += free;
	len   -= free;
    }

    while (len >= 64) {
	uint32_t state[4] = { ctx->a, ctx->b, ctx->c, ctx->d };
	Md4Transform(state, input);
	ctx->a = state[0]; ctx->b = state[1]; ctx->c = state[2]; ctx->d = state[3];
	input += 64;
	len   -= 64;
    }

    memcpy(ctx->buffer, input, len);
}

LIBHASH_INLINE_API void Md4Finalise(Md4Context *ctx, MD4_HASH *digest) {
    uint32_t used = ctx->lo & 0x3F;
    ctx->buffer[used++] = 0x80;
    uint32_t mfree = 64 - used;
    if (mfree < 8) {
	memset(&ctx->buffer[used], 0, mfree);
	uint32_t state[4] = { ctx->a, ctx->b, ctx->c, ctx->d };
	Md4Transform(state, ctx->buffer);
	ctx->a = state[0]; ctx->b = state[1]; ctx->c = state[2]; ctx->d = state[3];
	used = 0; mfree = 64;
    }
    memset(&ctx->buffer[used], 0, mfree - 8);
    uint64_t bits = (hash_cast(uint64_t,ctx->hi) << 29) | (ctx->lo << 3);
    for (int i = 0; i < 8; ++i)
	ctx->buffer[56 + i] = (uint8_t)(bits >> (8 * i));
    uint32_t state[4] = { ctx->a, ctx->b, ctx->c, ctx->d };
    Md4Transform(state, ctx->buffer);
    for (int i = 0; i < 4; ++i) {
	digest->bytes[i * 4 + 0] = (uint8_t)(state[i]);
	digest->bytes[i * 4 + 1] = (uint8_t)(state[i] >> 8);
	digest->bytes[i * 4 + 2] = (uint8_t)(state[i] >> 16);
	digest->bytes[i * 4 + 3] = (uint8_t)(state[i] >> 24);
    }
    memset(ctx, 0, sizeof(*ctx));
}

/* One-shot hash calculation */
LIBHASH_INLINE_API void Md4Calculate(const void *data, uint32_t len, MD4_HASH *digest) {
    Md4Context ctx;
    Md4Initialise(&ctx);
    Md4Update(&ctx, data, len);
    Md4Finalise(&ctx, digest);
}

#undef F4
#undef G4
#undef H4
#undef FF
#undef GG
#undef HH
#undef ROTL32

#endif /* __MD4_H__ */
