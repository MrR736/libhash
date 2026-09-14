/**
 * WjCryptLib_Sha3_256
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

#ifndef __SHA3_256_H__
#define __SHA3_256_H__

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

#define SHA3_256_BLOCK_SIZE 136
#define SHA3_256_HASH_SIZE  32

#define SHA3_256_ROUND_COUNT 24

#define SHA3_256_ROTL64(value, bits) \
	(((value) << (bits)) | ((value) >> (64 - (bits))))

typedef struct {
	uint64_t state[25];
	uint32_t curlen;
	uint8_t  buf[SHA3_256_BLOCK_SIZE];
} Sha3_256Context;

typedef struct {
	uint8_t bytes[SHA3_256_HASH_SIZE];
} SHA3_256_HASH;

#ifdef __cplusplus
extern "C" {
#endif

static const uint64_t Sha3_256RoundConstants[SHA3_256_ROUND_COUNT] = {
	0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808AULL,
	0x8000000080008000ULL,0x000000000000808BULL,0x0000000080000001ULL,
	0x8000000080008081ULL,0x8000000000008009ULL,0x000000000000008AULL,
	0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000AULL,
	0x000000008000808BULL,0x800000000000008BULL,0x8000000000008089ULL,
	0x8000000000008003ULL,0x8000000000008002ULL,0x8000000000000080ULL,
	0x000000000000800AULL,0x800000008000000AULL,0x8000000080008081ULL,
	0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL
};

static const uint32_t Sha3_256RotationOffsets[25] = {
	0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,
	41,45,15,21,8,18,2,61,56,14
};

/*
 * Sha3_256KeccakF1600
 *
 * Keccak-f[1600] permutation.
 *
 * The state consists of 25 64-bit lanes:
 *
 *     A[x + 5*y]
 *
 * Each permutation consists of:
 *
 *     Theta
 *     Rho
 *     Pi
 *     Chi
 *     Iota
 */
static inline void Sha3_256KeccakF1600(uint64_t state[25]) {
	uint64_t C[5]; uint64_t D[5]; uint64_t B[25];
	uint32_t x; uint32_t y; uint32_t i;
	for (i = 0; i < SHA3_256_ROUND_COUNT; i++) {
		// Theta
		for (x = 0; x < 5; x++) {
			C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
		}

		for (x = 0; x < 5; x++) {
			D[x] = C[(x + 4) % 5] ^ SHA3_256_ROTL64(C[(x + 1) % 5], 1);
		}

		for (y = 0; y < 5; y++) {
			for (x = 0; x < 5; x++) state[x + 5 * y] ^= D[x];
		}

		/*
		 * Rho + Pi
		 */
		for (y = 0; y < 5; y++) {
			for (x = 0; x < 5; x++) {
				uint32_t index = x + 5 * y;
				uint32_t target = y + 5 * ((2 * x + 3 * y) % 5);
				if (Sha3_256RotationOffsets[index] == 0) B[target] = state[index];
				else B[target] = SHA3_256_ROTL64(state[index],Sha3_256RotationOffsets[index]);
			}
		}

		// Chi
		for (y = 0; y < 5; y++) {
			for (x = 0; x < 5; x++) {
				state[x + 5 * y] = B[x + 5 * y] ^ ((~B[((x + 1) % 5) + 5 * y]) & B[((x + 2) % 5) + 5 * y]);
			}
		}

		// Iota
		state[0] ^= Sha3_256RoundConstants[i];
	}
}

/*
 * Sha3_256Absorb
 *
 * Absorb one complete 1088-bit block.
 *
 * SHA3-256:
 *
 *     rate = 1088 bits
 *          = 136 bytes
 *
 * Keccak lanes use little-endian byte ordering.
 */
static inline void Sha3_256Absorb(Sha3_256Context* Context,const uint8_t* Buffer) {
	uint32_t i;
	for (i = 0; i < SHA3_256_BLOCK_SIZE / 8; i++) {
		Context->state[i] ^=
			((uint64_t)Buffer[(i * 8) + 0]) | ((uint64_t)Buffer[(i * 8) + 1] << 8) |
			((uint64_t)Buffer[(i * 8) + 2] << 16) | ((uint64_t)Buffer[(i * 8) + 3] << 24) |
			((uint64_t)Buffer[(i * 8) + 4] << 32) | ((uint64_t)Buffer[(i * 8) + 5] << 40) |
			((uint64_t)Buffer[(i * 8) + 6] << 48) | ((uint64_t)Buffer[(i * 8) + 7] << 56);
	}
	Sha3_256KeccakF1600(Context->state);
}

/*
 * Sha3_256Initialise
 *
 * Initialises a SHA3-256 Context.
 */
LIBHASH_INLINE_API void Sha3_256Initialise(Sha3_256Context* Context) {
	memset(Context, 0, sizeof(*Context));
}

/*
 * Sha3_256Update
 *
 * Adds data to the SHA3-256 context.
 *
 * Data is absorbed in 136-byte blocks.
 */
LIBHASH_INLINE_API void Sha3_256Update(Sha3_256Context* Context,const void* Buffer,uint32_t BufferSize) {
	uint32_t n;
	if (Context->curlen > SHA3_256_BLOCK_SIZE) return;
	while (BufferSize > 0) {
		if (Context->curlen == 0 && BufferSize >= SHA3_256_BLOCK_SIZE) {
			Sha3_256Absorb(Context,uhash_c_cast(const uint8_t*, Buffer));
			Buffer = uhash_c_cast(const uint8_t*, Buffer) + SHA3_256_BLOCK_SIZE;
			BufferSize -= SHA3_256_BLOCK_SIZE;
		} else {
			n = SHA3_256_BLOCK_SIZE - Context->curlen;
			if (n > BufferSize) n = BufferSize;
			memcpy(Context->buf + Context->curlen,Buffer,hash_cast(size_t, n));
			Context->curlen += n;
			Buffer = uhash_c_cast(const uint8_t*, Buffer) + n;
			BufferSize -= n;
			if (Context->curlen == SHA3_256_BLOCK_SIZE) {
				Sha3_256Absorb(Context,Context->buf);
				Context->curlen = 0;
			}
		}
	}
}

/*
 * Sha3_256Finalise
 *
 * Performs the final SHA3-256 calculation.
 *
 * SHA-3 domain separation:
 *
 *     0x06
 *
 * followed by pad10*1, whose final bit is:
 *
 *     0x80
 */
LIBHASH_INLINE_API void Sha3_256Finalise(Sha3_256Context* Context,SHA3_256_HASH* Digest) {
	uint32_t i; uint32_t n;
	if (Context->curlen >= SHA3_256_BLOCK_SIZE) return;

	// SHA-3 domain separation suffix.
	Context->buf[Context->curlen++] = 0x06;

	// Zero-fill the remaining rate portion.
	while (Context->curlen < SHA3_256_BLOCK_SIZE)
		Context->buf[Context->curlen++] = 0;

	// Final bit of pad10*1.
	Context->buf[SHA3_256_BLOCK_SIZE - 1] |= 0x80;

	// Absorb final block.
	Sha3_256Absorb(Context,Context->buf);

	/*
	 * SHA3-256 produces 32 bytes.
	 *
	 * The first four 64-bit lanes contain the complete
	 * digest. Keccak uses little-endian lanes.
	 */
	for (i = 0; i < SHA3_256_HASH_SIZE / 8; i++) {
		n = i * 8;
		Digest->bytes[n + 0] = hash_cast(uint8_t,(Context->state[i] >> 0) & 255);
		Digest->bytes[n + 1] = hash_cast(uint8_t,(Context->state[i] >> 8) & 255);
		Digest->bytes[n + 2] = hash_cast(uint8_t,(Context->state[i] >> 16) & 255);
		Digest->bytes[n + 3] = hash_cast(uint8_t,(Context->state[i] >> 24) & 255);
		Digest->bytes[n + 4] = hash_cast(uint8_t,(Context->state[i] >> 32) & 255);
		Digest->bytes[n + 5] = hash_cast(uint8_t,(Context->state[i] >> 40) & 255);
		Digest->bytes[n + 6] = hash_cast(uint8_t,(Context->state[i] >> 48) & 255);
		Digest->bytes[n + 7] = hash_cast(uint8_t,(Context->state[i] >> 56) & 255);
	}
}

/*
 * Sha3_256Calculate
 *
 * Combines Sha3_256Initialise, Sha3_256Update,
 * and Sha3_256Finalise into one function.
 */
LIBHASH_INLINE_API void Sha3_256Calculate(const void* Buffer,uint32_t BufferSize,SHA3_256_HASH* Digest) {
	Sha3_256Context context;
	Sha3_256Initialise(&context);
	Sha3_256Update(&context, Buffer, BufferSize);
	Sha3_256Finalise(&context, Digest);
}

#ifdef __cplusplus
}
#endif

#endif /* __SHA3_256_H__ */
