/**
 * WjCryptLib_Sha224
 *
 * Copyright (C) 2025 MrR736 <MrR736@users.github.com>
 *
 * Original Author: Steve Reid <sreid@sea-to-sky.net>
 * Contributions by: James H. Brown <jbrown@burgoyne.com>, Saul Kravitz <Saul.Kravitz@celera.com>,
 * Ralph Giles <giles@ghostscript.com>
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

#ifndef __SHA224_H__
#define __SHA224_H__

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

#define S224(value, bits)  (((value) >> (bits)) | ((value) << (32 - (bits))))
#define Sha224Round(a, b, c, d, e, f, g, h, i) \
	t0 = h + (S224(e,6)^S224(e,11)^S224(e,25)) + (g^(e&(f^g))) + SHAK224[i] + W[i]; \
	t1 = (S224(a,2)^S224(a,13)^S224(a,22))+(((a|b)&c)|(a&b)); \
	d += t0; \
	h  = t0+t1;

#define SHA224_BLOCK_SIZE 64
#define SHA224_HASH_SIZE  28

typedef struct {
    uint64_t length;
    uint32_t state[8];
    uint32_t curlen;
    uint8_t  buf[SHA224_BLOCK_SIZE];
} Sha224Context;

typedef struct {
    uint8_t bytes[SHA224_HASH_SIZE];
} SHA224_HASH;

#ifdef __cplusplus
extern "C" {
#endif

static const uint32_t SHAK224[SHA224_BLOCK_SIZE] = {
	0x428a2f98UL,0x71374491UL,0xb5c0fbcfUL,0xe9b5dba5UL,0x3956c25bUL,
	0x59f111f1UL,0x923f82a4UL,0xab1c5ed5UL,0xd807aa98UL,0x12835b01UL,
	0x243185beUL,0x550c7dc3UL,0x72be5d74UL,0x80deb1feUL,0x9bdc06a7UL,
	0xc19bf174UL,0xe49b69c1UL,0xefbe4786UL,0x0fc19dc6UL,0x240ca1ccUL,
	0x2de92c6fUL,0x4a7484aaUL,0x5cb0a9dcUL,0x76f988daUL,0x983e5152UL,
	0xa831c66dUL,0xb00327c8UL,0xbf597fc7UL,0xc6e00bf3UL,0xd5a79147UL,
	0x06ca6351UL,0x14292967UL,0x27b70a85UL,0x2e1b2138UL,0x4d2c6dfcUL,
	0x53380d13UL,0x650a7354UL,0x766a0abbUL,0x81c2c92eUL,0x92722c85UL,
	0xa2bfe8a1UL,0xa81a664bUL,0xc24b8b70UL,0xc76c51a3UL,0xd192e819UL,
	0xd6990624UL,0xf40e3585UL,0x106aa070UL,0x19a4c116UL,0x1e376c08UL,
	0x2748774cUL,0x34b0bcb5UL,0x391c0cb3UL,0x4ed8aa4aUL,0x5b9cca4fUL,
	0x682e6ff3UL,0x748f82eeUL,0x78a5636fUL,0x84c87814UL,0x8cc70208UL,
	0x90befffaUL,0xa4506cebUL,0xbef9a3f7UL,0xc67178f2UL
};

/*
 * Sha224TransformFunction
 */
static inline void Sha224TransformFunction(Sha224Context* Context, const uint8_t* Buffer) {
	uint32_t S[8], W[SHA224_BLOCK_SIZE], t0, t1, t;
	int i;
	for(i=0; i<8; i++) { S[i] = Context->state[i]; }
	for(i=0; i<16; i++) {
		W[i] =	(hash_cast(uint32_t,((Buffer+(4*i))[0]&255))<<24) |
			(hash_cast(uint32_t,((Buffer+(4*i))[1]&255))<<16) |
			(hash_cast(uint32_t,((Buffer+(4*i))[2]&255))<<8)  |
			(hash_cast(uint32_t,((Buffer+(4*i))[3]&255)));
	}
	for(i=16; i<SHA224_BLOCK_SIZE; i++) {
		W[i] =	(S224(W[i - 2],17) ^ S224(W[i - 2],19) ^ ((W[i - 2]&0xFFFFFFFFUL) >> (10))) + W[i - 7] +
			(S224(W[i - 15],7) ^ S224(W[i - 15],18) ^ ((W[i - 15] & 0xFFFFFFFFUL) >> (3))) + W[i - 16];
	}
	for(i=0; i<SHA224_BLOCK_SIZE; i++) {
		Sha224Round(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], i);
		t = S[7]; S[7] = S[6]; S[6] = S[5]; S[5] = S[4]; S[4] = S[3];
		S[3] = S[2]; S[2] = S[1]; S[1] = S[0]; S[0] = t;
	}
	for(i=0; i<8; i++) Context->state[i] += S[i];
}

/*
 * Sha224Initialise
 */
LIBHASH_INLINE_API void Sha224Initialise(Sha224Context* Context) {
	Context->curlen = 0;
	Context->length = 0;
	Context->state[0] = 0xC1059ED8UL;
	Context->state[1] = 0x367CD507UL;
	Context->state[2] = 0x3070DD17UL;
	Context->state[3] = 0xF70E5939UL;
	Context->state[4] = 0xFFC00B31UL;
	Context->state[5] = 0x68581511UL;
	Context->state[6] = 0x64F98FA7UL;
	Context->state[7] = 0xBEFA4FA4UL;
}

/*
 * Sha224Update
 */
LIBHASH_INLINE_API void Sha224Update(Sha224Context* Context, const void* Buffer, uint32_t BufferSize) {
	uint32_t n;
	if(Context->curlen > sizeof(Context->buf)) return;
	while(BufferSize > 0) {
		if(Context->curlen == 0 && BufferSize >= SHA224_BLOCK_SIZE) {
			Sha224TransformFunction(Context, hash_c_cast(uint8_t*, Buffer));
			Context->length += (SHA224_BLOCK_SIZE * 8);
			Buffer = hash_c_cast(uint8_t*, Buffer) + SHA224_BLOCK_SIZE;
			BufferSize -= SHA224_BLOCK_SIZE;
		} else {
			n = ((BufferSize < (SHA224_BLOCK_SIZE - Context->curlen)) ? BufferSize : (SHA224_BLOCK_SIZE - Context->curlen));
			memcpy(Context->buf + Context->curlen, Buffer, hash_cast(size_t, n));
			Context->curlen += n;
			Buffer = hash_c_cast(uint8_t*, Buffer) + n;
			BufferSize -= n;
			if(Context->curlen == SHA224_BLOCK_SIZE) {
				Sha224TransformFunction(Context, Context->buf);
				Context->length += (SHA224_BLOCK_SIZE * 8);
				Context->curlen = 0;
			}
		}
	}
}

/*
 * Sha224Finalise
 */
LIBHASH_INLINE_API void Sha224Finalise(Sha224Context* Context, SHA224_HASH* Digest) {
	if(Context->curlen >= sizeof(Context->buf)) return;
	Context->length += (Context->curlen * 8);
	Context->buf[Context->curlen++] = hash_cast(uint8_t, 0x80);
	if(Context->curlen > 56) {
		while(Context->curlen < SHA224_BLOCK_SIZE) Context->buf[Context->curlen++] = 0;
		Sha224TransformFunction(Context, Context->buf);
		Context->curlen = 0;
	}
	while(Context->curlen < 56) Context->buf[Context->curlen++] = 0;

	(Context->buf + 56)[0] = hash_cast(uint8_t,(((Context->length) >> 56) & 255));
	(Context->buf + 56)[1] = hash_cast(uint8_t,(((Context->length) >> 48) & 255));
	(Context->buf + 56)[2] = hash_cast(uint8_t,(((Context->length) >> 40) & 255));
	(Context->buf + 56)[3] = hash_cast(uint8_t,(((Context->length) >> 32) & 255));
	(Context->buf + 56)[4] = hash_cast(uint8_t,(((Context->length) >> 24) & 255));
	(Context->buf + 56)[5] = hash_cast(uint8_t,(((Context->length) >> 16) & 255));
	(Context->buf + 56)[6] = hash_cast(uint8_t,(((Context->length) >> 8) & 255));
	(Context->buf + 56)[7] = hash_cast(uint8_t,((Context->length) & 255));

	Sha224TransformFunction(Context, Context->buf);

	// SHA-224 outputs only the first 7 words of SHA-256 state
	for(int i=0; i<7; i++) {
		(Digest->bytes + (4 * i))[0] = hash_cast(uint8_t, ((Context->state[i] >> 24) & 255));
		(Digest->bytes + (4 * i))[1] = hash_cast(uint8_t, ((Context->state[i] >> 16) & 255));
		(Digest->bytes + (4 * i))[2] = hash_cast(uint8_t, ((Context->state[i] >> 8) & 255));
		(Digest->bytes + (4 * i))[3] = hash_cast(uint8_t, (Context->state[i] & 255));
	}
}

/*
 * Sha224Calculate
 */
LIBHASH_INLINE_API void Sha224Calculate(const void* Buffer, uint32_t BufferSize, SHA224_HASH* Digest) {
	Sha224Context context;
	Sha224Initialise(&context);
	Sha224Update(&context, Buffer, BufferSize);
	Sha224Finalise(&context, Digest);
}

#ifdef __cplusplus
}
#endif

#endif /* __SHA224_H__ */
