/**
 * WjCryptLib_Sha3_512
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

#ifndef __SHA3_512_H__
#define __SHA3_512_H__

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

#define SHA3_512_BLOCK_SIZE 72
#define SHA3_512_HASH_SIZE  64

#define SHA3_512_ROTL64(value, bits) \
	((bits) == 0 ? (value) : (((value) << (bits)) | ((value) >> (64 - (bits)))))

#define SHA3_512_ROUND_COUNT 24

typedef struct {
	uint64_t state[25];
	uint32_t curlen;
	uint8_t  buf[SHA3_512_BLOCK_SIZE];
} Sha3_512Context;

typedef struct {
	uint8_t bytes[SHA3_512_HASH_SIZE];
} SHA3_512_HASH;


#ifdef __cplusplus
extern "C" {
#endif


static const uint64_t Sha3_512RoundConstants[SHA3_512_ROUND_COUNT] = {
	0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808AULL,
	0x8000000080008000ULL,0x000000000000808BULL,0x0000000080000001ULL,
	0x8000000080008081ULL,0x8000000000008009ULL,0x000000000000008AULL,
	0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000AULL,
	0x000000008000808BULL,0x800000000000008BULL,0x8000000000008089ULL,
	0x8000000000008003ULL,0x8000000000008002ULL,0x8000000000000080ULL,
	0x000000000000800AULL,0x800000008000000AULL,0x8000000080008081ULL,
	0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL
};

static const uint32_t Sha3_512RotationOffsets[25] = {
	0, 1, 62, 28, 27,
	36, 44, 6, 55, 20,
	3, 10, 43, 25, 39,
	41, 45, 15, 21, 8,
	18, 2, 61, 56, 14
};

/*
 * Sha3_512KeccakF1600
 *
 * Keccak-f[1600] permutation.
 *
 * The state consists of 25 64-bit lanes arranged as:
 *
 *     A[x + 5*y]
 *
 * The permutation consists of 24 rounds:
 *
 *     Theta
 *     Rho
 *     Pi
 *     Chi
 *     Iota
 */
static inline void Sha3_512KeccakF1600(uint64_t state[25]) {
	uint64_t C[5];
	uint64_t D[5];
	uint64_t B[25];
	uint32_t x;
	uint32_t y;
	uint32_t i;

	for (i = 0; i < SHA3_512_ROUND_COUNT; i++) {
		/*
		 * Theta
		 *
		 * C[x] = A[x,0] ^ A[x,1] ^ A[x,2] ^ A[x,3] ^ A[x,4]
		 *
		 * D[x] = C[x-1] ^ ROT(C[x+1],1)
		 */
		for (x = 0; x < 5; x++) {
			C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
		}

		for (x = 0; x < 5; x++) { D[x] = C[(x + 4) % 5] ^ SHA3_512_ROTL64(C[(x + 1) % 5], 1); }
		for (y = 0; y < 5; y++) { for (x = 0; x < 5; x++) state[x + 5 * y] ^= D[x]; }

		/*
		 * Rho + Pi
		 *
		 * B[y, 2*x+3*y] = ROT(A[x,y], r[x,y])
		 */
		for (y = 0; y < 5; y++) {
			for (x = 0; x < 5; x++) {
				uint32_t index = x + 5 * y;
				uint32_t target = y + 5 * ((2 * x + 3 * y) % 5);
				B[target] = SHA3_512_ROTL64(state[index],Sha3_512RotationOffsets[index]);
			}
		}

		/*
		 * Chi
		 *
		 * A[x,y] = B[x,y] ^
		 *          ((~B[x+1,y]) & B[x+2,y])
		 */
		for (y = 0; y < 5; y++) {
			for (x = 0; x < 5; x++) {
				state[x + 5 * y] = B[x + 5 * y] ^ ((~B[((x + 1) % 5) + 5 * y]) & B[((x + 2) % 5) + 5 * y]);
			}
		}

		/*
		 * Iota
		 */
		state[0] ^= Sha3_512RoundConstants[i];
	}
}


/*
 * Sha3_512Absorb
 *
 * Absorb one complete 576-bit block into the Keccak state.
 *
 * SHA-3 uses little-endian byte ordering for each 64-bit lane.
 */
static inline void Sha3_512Absorb(Sha3_512Context* Context,const uint8_t* Buffer) {
	uint32_t i;
	for (i = 0; i < SHA3_512_BLOCK_SIZE / 8; i++) {
		Context->state[i] ^=
			((uint64_t)Buffer[(i * 8) + 0]) |
			((uint64_t)Buffer[(i * 8) + 1] << 8) |
			((uint64_t)Buffer[(i * 8) + 2] << 16) |
			((uint64_t)Buffer[(i * 8) + 3] << 24) |
			((uint64_t)Buffer[(i * 8) + 4] << 32) |
			((uint64_t)Buffer[(i * 8) + 5] << 40) |
			((uint64_t)Buffer[(i * 8) + 6] << 48) |
			((uint64_t)Buffer[(i * 8) + 7] << 56);
	}
	Sha3_512KeccakF1600(Context->state);
}


/*
 * Sha3_512Initialise
 *
 * Initialises a SHA3-512 context.
 */
LIBHASH_INLINE_API void Sha3_512Initialise(Sha3_512Context* Context) {
	memset(Context, 0, sizeof(*Context));
}


/*
 * Sha3_512Update
 *
 * Adds data to the SHA3-512 context.
 *
 * Data is absorbed in 72-byte blocks because SHA3-512 has:
 *
 *     rate = 1600 - 2*512 = 576 bits = 72 bytes
 */
LIBHASH_INLINE_API void Sha3_512Update(Sha3_512Context* Context,const void* Buffer,uint32_t BufferSize) {
	uint32_t n;
	if (Context->curlen > SHA3_512_BLOCK_SIZE) return;
	while (BufferSize > 0) {
		if (Context->curlen == 0 && BufferSize >= SHA3_512_BLOCK_SIZE) {
			Sha3_512Absorb(Context,uhash_c_cast(const uint8_t*, Buffer));
			Buffer = uhash_c_cast(const uint8_t*, Buffer) + SHA3_512_BLOCK_SIZE;
			BufferSize -= SHA3_512_BLOCK_SIZE;
		} else {
			n = SHA3_512_BLOCK_SIZE - Context->curlen;
			if (n > BufferSize) n = BufferSize;
			memcpy(Context->buf + Context->curlen,Buffer,hash_cast(size_t, n));
			Context->curlen += n;
			Buffer = uhash_c_cast(const uint8_t*, Buffer) + n;
			BufferSize -= n;
			if (Context->curlen == SHA3_512_BLOCK_SIZE) {
				Sha3_512Absorb(Context,Context->buf);
				Context->curlen = 0;
			}
		}
	}
}


/*
 * Sha3_512Finalise
 *
 * Applies SHA-3's domain separation and padding:
 *
 *     0x06 ... 0x80
 *
 * This is the Keccak pad10*1 padding combined with
 * SHA-3's domain separation suffix.
 */
LIBHASH_INLINE_API void Sha3_512Finalise(Sha3_512Context* Context,SHA3_512_HASH* Digest) {
	uint32_t i;
	uint32_t n;
	if (Context->curlen >= SHA3_512_BLOCK_SIZE) return;

	/*
	 * SHA-3 domain separation suffix:
	 *
	 *     0x06 = 01 || 10
	 *
	 * The final bit of the block is set separately below.
	 */
	Context->buf[Context->curlen++] = 0x06;

	// Zero-fill the remainder of the rate portion.
	while (Context->curlen < SHA3_512_BLOCK_SIZE) Context->buf[Context->curlen++] = 0;

	// Final bit of pad10*1.
	Context->buf[SHA3_512_BLOCK_SIZE - 1] |= 0x80;

	// Absorb final block.
	Sha3_512Absorb(Context, Context->buf);

	/*
	 * SHA3-512 output is 64 bytes.
	 *
	 * The first eight lanes contain 64 bytes exactly.
	 * Keccak lanes are little-endian.
	 */
	for (i = 0; i < SHA3_512_HASH_SIZE / 8; i++) {
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
 * Sha3_512Calculate
 *
 * Combines Sha3_512Initialise, Sha3_512Update,
 * and Sha3_512Finalise into one function.
 */
LIBHASH_INLINE_API void Sha3_512Calculate(const void* Buffer,uint32_t BufferSize,SHA3_512_HASH* Digest) {
	Sha3_512Context context;
	Sha3_512Initialise(&context);
	Sha3_512Update(&context, Buffer, BufferSize);
	Sha3_512Finalise(&context, Digest);
}


#ifdef __cplusplus
}
#endif

#endif /* __SHA3_512_H__ */
// "abc" out a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26 ???
