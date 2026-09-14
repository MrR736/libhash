/**
 * WjCryptLib_Sha512/256
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

#ifndef __SHA512_256_H__
#define __SHA512_256_H__

#include <stdint.h>
#include <memory.h>

#if defined(_MSC_VER) && _MSC_VER < 1900 && !defined(inline)
#define inline __inline
#endif

#ifndef LIBHASH_VISIBILITY
#if (defined(__GNUC__) && (__GNUC__ >= 4) && (__GNUC_MINOR__ > 2)) || \
(defined(__has_attribute) && __has_attribute(visibility))
#define LIBHASH_VISIBILITY(V) __attribute__ ((visibility (#V)))
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

#define SHA512_256_BLOCK_SIZE 128
#define SHA512_256_HASH_SIZE  32

#define S512_256(value, bits) (((value) >> (bits)) | ((value) << (64 - (bits))))
#define SHA512_256_CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define SHA512_256_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA512_256_BSIG0(x) (S512_256((x), 28) ^ S512_256((x), 34) ^ S512_256((x), 39))
#define SHA512_256_BSIG1(x) (S512_256((x), 14) ^ S512_256((x), 18) ^ S512_256((x), 41))
#define SHA512_256_SSIG0(x) (S512_256((x), 1) ^ S512_256((x), 8) ^ ((x) >> 7))
#define SHA512_256_SSIG1(x) (S512_256((x), 19) ^ S512_256((x), 61) ^ ((x) >> 6))

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint64_t length;
	uint64_t state[8];
	uint32_t curlen;
	uint8_t buf[SHA512_256_BLOCK_SIZE];
} Sha512_256Context;


typedef struct {
	uint8_t bytes[SHA512_256_HASH_SIZE];
} SHA512_256_HASH;

// SHA-512 round constants.
static const uint64_t SHA512_256_K[80] = {
	UINT64_C(0x428a2f98d728ae22),UINT64_C(0x7137449123ef65cd),UINT64_C(0xb5c0fbcfec4d3b2f),UINT64_C(0xe9b5dba58189dbbc),
	UINT64_C(0x3956c25bf348b538),UINT64_C(0x59f111f1b605d019),UINT64_C(0x923f82a4af194f9b),UINT64_C(0xab1c5ed5da6d8118),
	UINT64_C(0xd807aa98a3030242),UINT64_C(0x12835b0145706fbe),UINT64_C(0x243185be4ee4b28c),UINT64_C(0x550c7dc3d5ffb4e2),
	UINT64_C(0x72be5d74f27b896f),UINT64_C(0x80deb1fe3b1696b1),UINT64_C(0x9bdc06a725c71235),UINT64_C(0xc19bf174cf692694),
	UINT64_C(0xe49b69c19ef14ad2),UINT64_C(0xefbe4786384f25e3),UINT64_C(0x0fc19dc68b8cd5b5),UINT64_C(0x240ca1cc77ac9c65),
	UINT64_C(0x2de92c6f592b0275),UINT64_C(0x4a7484aa6ea6e483),UINT64_C(0x5cb0a9dcbd41fbd4),UINT64_C(0x76f988da831153b5),
	UINT64_C(0x983e5152ee66dfab),UINT64_C(0xa831c66d2db43210),UINT64_C(0xb00327c898fb213f),UINT64_C(0xbf597fc7beef0ee4),
	UINT64_C(0xc6e00bf33da88fc2),UINT64_C(0xd5a79147930aa725),UINT64_C(0x06ca6351e003826f),UINT64_C(0x142929670a0e6e70),
	UINT64_C(0x27b70a8546d22ffc),UINT64_C(0x2e1b21385c26c926),UINT64_C(0x4d2c6dfc5ac42aed),UINT64_C(0x53380d139d95b3df),
	UINT64_C(0x650a73548baf63de),UINT64_C(0x766a0abb3c77b2a8),UINT64_C(0x81c2c92e47edaee6),UINT64_C(0x92722c851482353b),
	UINT64_C(0xa2bfe8a14cf10364),UINT64_C(0xa81a664bbc423001),UINT64_C(0xc24b8b70d0f89791),UINT64_C(0xc76c51a30654be30),
	UINT64_C(0xd192e819d6ef5218),UINT64_C(0xd69906245565a910),UINT64_C(0xf40e35855771202a),UINT64_C(0x106aa07032bbd1b8),
	UINT64_C(0x19a4c116b8d2d0c8),UINT64_C(0x1e376c085141ab53),UINT64_C(0x2748774cdf8eeb99),UINT64_C(0x34b0bcb5e19b48a8),
	UINT64_C(0x391c0cb3c5c95a63),UINT64_C(0x4ed8aa4ae3418acb),UINT64_C(0x5b9cca4f7763e373),UINT64_C(0x682e6ff3d6b2b8a3),
	UINT64_C(0x748f82ee5defb2fc),UINT64_C(0x78a5636f43172f60),UINT64_C(0x84c87814a1f0ab72),UINT64_C(0x8cc702081a6439ec),
	UINT64_C(0x90befffa23631e28),UINT64_C(0xa4506cebde82bde9),UINT64_C(0xbef9a3f7b2c67915),UINT64_C(0xc67178f2e372532b),
	UINT64_C(0xca273eceea26619c),UINT64_C(0xd186b8c721c0c207),UINT64_C(0xeada7dd6cde0eb1e),UINT64_C(0xf57d4f7fee6ed178),
	UINT64_C(0x06f067aa72176fba),UINT64_C(0x0a637dc5a2c898a6),UINT64_C(0x113f9804bef90dae),UINT64_C(0x1b710b35131c471b),
	UINT64_C(0x28db77f523047d84),UINT64_C(0x32caab7b40c72493),UINT64_C(0x3c9ebe0a15c9bebc),UINT64_C(0x431d67c49c100d4c),
	UINT64_C(0x4cc5d4becb3e42b6),UINT64_C(0x597f299cfc657e2a),UINT64_C(0x5fcb6fab3ad6faec),UINT64_C(0x6c44198c4a475817)
};

/*
 * SHA-512/256 initial hash value.
 */
static const uint64_t SHA512_256_IV[8] = {
	UINT64_C(0x22312194fc2bf72c),UINT64_C(0x9f555fa3c84c64c2),UINT64_C(0x2393b86b6f53b151),UINT64_C(0x963877195940eabd),
	UINT64_C(0x96283ee2a88effe3),UINT64_C(0xbe5e1e2553863992),UINT64_C(0x2b0199fc2c85b8aa),UINT64_C(0x0eb72ddc81c52ca2)
};


static inline void Sha512_256TransformFunction(Sha512_256Context* context,const uint8_t* data) {
	uint64_t S[8]; uint64_t W[80];
	uint64_t t1; uint64_t t2;
	int i;
	for (i = 0; i < 8; ++i) S[i] = context->state[i];
	for (i = 0; i < 16; ++i) {
		W[i] =
			((uint64_t)data[i * 8 + 0] << 56) | ((uint64_t)data[i * 8 + 1] << 48) |
			((uint64_t)data[i * 8 + 2] << 40) | ((uint64_t)data[i * 8 + 3] << 32) |
			((uint64_t)data[i * 8 + 4] << 24) | ((uint64_t)data[i * 8 + 5] << 16) |
			((uint64_t)data[i * 8 + 6] << 8) | ((uint64_t)data[i * 8 + 7]);
	}

	for (i = 16; i < 80; ++i) {
		W[i] = SHA512_256_SSIG1(W[i - 2]) + W[i - 7] + SHA512_256_SSIG0(W[i - 15]) + W[i - 16];
	}

	for (i = 0; i < 80; ++i) {
		t1 = S[7] + SHA512_256_BSIG1(S[4]) + SHA512_256_CH(S[4], S[5], S[6]) + SHA512_256_K[i] + W[i];
		t2 = SHA512_256_BSIG0(S[0]) + SHA512_256_MAJ(S[0], S[1], S[2]);
		S[7] = S[6]; S[6] = S[5]; S[5] = S[4]; S[4] = S[3] + t1;
		S[3] = S[2]; S[2] = S[1]; S[1] = S[0]; S[0] = t1 + t2;
	}
	for (i = 0; i < 8; ++i) context->state[i] += S[i];
	memset(W, 0, sizeof(W));
	memset(S, 0, sizeof(S));
}

LIBHASH_INLINE_API void Sha512_256Initialise(Sha512_256Context* context) {
	memcpy(context->state,SHA512_256_IV,sizeof(SHA512_256_IV));
	context->length = 0;
	context->curlen = 0;
}

LIBHASH_INLINE_API void Sha512_256Update(Sha512_256Context* context,const void* input,uint32_t length) {
	const uint8_t* data = (const uint8_t*)input;
	while (length > 0) {
		uint32_t n = SHA512_256_BLOCK_SIZE - context->curlen;
		if (n > length) n = length;
		memcpy(context->buf + context->curlen,data,n);
		context->curlen += n;
		data += n;
		length -= n;
		if (context->curlen == SHA512_256_BLOCK_SIZE) {
			Sha512_256TransformFunction(context,context->buf);
			context->length += (uint64_t)SHA512_256_BLOCK_SIZE * 8;
			context->curlen = 0;
		}
	}
}

LIBHASH_INLINE_API void Sha512_256Finalise(Sha512_256Context* context,SHA512_256_HASH* digest) {
	uint64_t bit_length;
	uint32_t i;
	bit_length = context->length + ((uint64_t)context->curlen * 8);
	context->buf[context->curlen++] = 0x80;
	if (context->curlen > 112) {
		while (context->curlen < 128) context->buf[context->curlen++] = 0;
		Sha512_256TransformFunction(context,context->buf);
		context->curlen = 0;
	}
	while (context->curlen < 112) context->buf[context->curlen++] = 0;

	/*
	 * SHA-512 uses a 128-bit message length field.
	 *
	 * This context tracks the low 64 bits of the
	 * message length, matching the existing SHA-512
	 * implementation.
	 */
	for (i = 0; i < 8; ++i) context->buf[112 + i] = 0;
	for (i = 0; i < 8; ++i) context->buf[120 + i] = (uint8_t)(bit_length >> (56 - i * 8));
	Sha512_256TransformFunction(context,context->buf);
	for (i = 0; i < SHA512_256_HASH_SIZE; ++i) {
		digest->bytes[i] = (uint8_t)(context->state[i / 8] >> (56 - (i % 8) * 8));
	}
	memset(context,0,sizeof(*context));
}

LIBHASH_INLINE_API void Sha512_256Calculate(const void* input,uint32_t length,SHA512_256_HASH* digest) {
	Sha512_256Context context;
	Sha512_256Initialise(&context);
	Sha512_256Update(&context,input,length);
	Sha512_256Finalise(&context,digest);
}

#ifdef __cplusplus
}
#endif

#endif
