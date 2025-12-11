/**
 * WjCryptLib_Md5
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

#ifndef __MD5_H__
#define __MD5_H__

//  IMPORTS
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

#define F5(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define G5(x, y, z) ((y) ^ ((z) & ((x) ^ (y))))
#define H5(x, y, z) ((x) ^ (y) ^ (z))
#define I5(x, y, z) ((y) ^ ((x) | ~(z)))

#define MD5_STEP(f, a, b, c, d, x, t, s) \
	(a) += f((b), (c), (d)) + (x) + (t); \
	(a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s)))); \
	(a) += (b);

#define MD5_SET(n) (ctx->block[(n)] = \
	(hash_cast(uint32_t,ptr[(n) * 4 + 0]) << 0) | (hash_cast(uint32_t,ptr[(n) * 4 + 1]) << 8) |\
	(hash_cast(uint32_t,ptr[(n) * 4 + 2]) << 16) | (hash_cast(uint32_t,ptr[(n) * 4 + 3]) << 24))

#define MD5_HASH_SIZE  16

typedef struct {
	uint32_t lo;
	uint32_t hi;
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
	uint8_t  buffer[64];
	uint32_t block[16];
} Md5Context;

typedef struct {
	uint8_t bytes[MD5_HASH_SIZE];
} MD5_HASH;

#ifdef __cplusplus
extern "C" {
#endif

/*
 *  Md5TransformFunction
 *
 *  This processes one or more 64-byte data blocks, but does NOT update the bit counters. There are no alignment
 *  requirements.
 */
static inline void* Md5TransformFunction(Md5Context* ctx, const void* data, uintmax_t size) {
	uint32_t a, b, c, d, saved_a, saved_b, saved_c, saved_d;
	uint8_t* ptr = hash_c_cast(uint8_t*,data);
	a = ctx->a;
	b = ctx->b;
	c = ctx->c;
	d = ctx->d;
	do {
		saved_a = a;
		saved_b = b;
		saved_c = c;
		saved_d = d;
		// Round 1
		MD5_STEP(F5, a, b, c, d, MD5_SET(0),  0xd76aa478, 7)
		MD5_STEP(F5, d, a, b, c, MD5_SET(1),  0xe8c7b756, 12)
		MD5_STEP(F5, c, d, a, b, MD5_SET(2),  0x242070db, 17)
		MD5_STEP(F5, b, c, d, a, MD5_SET(3),  0xc1bdceee, 22)
		MD5_STEP(F5, a, b, c, d, MD5_SET(4),  0xf57c0faf, 7)
		MD5_STEP(F5, d, a, b, c, MD5_SET(5),  0x4787c62a, 12)
		MD5_STEP(F5, c, d, a, b, MD5_SET(6),  0xa8304613, 17)
		MD5_STEP(F5, b, c, d, a, MD5_SET(7),  0xfd469501, 22)
		MD5_STEP(F5, a, b, c, d, MD5_SET(8),  0x698098d8, 7)
		MD5_STEP(F5, d, a, b, c, MD5_SET(9),  0x8b44f7af, 12)
		MD5_STEP(F5, c, d, a, b, MD5_SET(10), 0xffff5bb1, 17)
		MD5_STEP(F5, b, c, d, a, MD5_SET(11), 0x895cd7be, 22)
		MD5_STEP(F5, a, b, c, d, MD5_SET(12), 0x6b901122, 7)
		MD5_STEP(F5, d, a, b, c, MD5_SET(13), 0xfd987193, 12)
		MD5_STEP(F5, c, d, a, b, MD5_SET(14), 0xa679438e, 17)
		MD5_STEP(F5, b, c, d, a, MD5_SET(15), 0x49b40821, 22)
		// Round 2
		MD5_STEP(G5, a, b, c, d, ctx->block[1],  0xf61e2562, 5)
		MD5_STEP(G5, d, a, b, c, ctx->block[6],  0xc040b340, 9)
		MD5_STEP(G5, c, d, a, b, ctx->block[11], 0x265e5a51, 14)
		MD5_STEP(G5, b, c, d, a, ctx->block[0],  0xe9b6c7aa, 20)
		MD5_STEP(G5, a, b, c, d, ctx->block[5],  0xd62f105d, 5)
		MD5_STEP(G5, d, a, b, c, ctx->block[10], 0x02441453, 9)
		MD5_STEP(G5, c, d, a, b, ctx->block[15], 0xd8a1e681, 14)
		MD5_STEP(G5, b, c, d, a, ctx->block[4],  0xe7d3fbc8, 20)
		MD5_STEP(G5, a, b, c, d, ctx->block[9],  0x21e1cde6, 5)
		MD5_STEP(G5, d, a, b, c, ctx->block[14], 0xc33707d6, 9)
		MD5_STEP(G5, c, d, a, b, ctx->block[3],  0xf4d50d87, 14)
		MD5_STEP(G5, b, c, d, a, ctx->block[8],  0x455a14ed, 20)
		MD5_STEP(G5, a, b, c, d, ctx->block[13], 0xa9e3e905, 5)
		MD5_STEP(G5, d, a, b, c, ctx->block[2],  0xfcefa3f8, 9)
		MD5_STEP(G5, c, d, a, b, ctx->block[7],  0x676f02d9, 14)
		MD5_STEP(G5, b, c, d, a, ctx->block[12], 0x8d2a4c8a, 20)
		// Round 3
		MD5_STEP(H5, a, b, c, d, ctx->block[5],  0xfffa3942, 4)
		MD5_STEP(H5, d, a, b, c, ctx->block[8],  0x8771f681, 11)
		MD5_STEP(H5, c, d, a, b, ctx->block[11], 0x6d9d6122, 16)
		MD5_STEP(H5, b, c, d, a, ctx->block[14], 0xfde5380c, 23)
		MD5_STEP(H5, a, b, c, d, ctx->block[1],  0xa4beea44, 4)
		MD5_STEP(H5, d, a, b, c, ctx->block[4],  0x4bdecfa9, 11)
		MD5_STEP(H5, c, d, a, b, ctx->block[7],  0xf6bb4b60, 16)
		MD5_STEP(H5, b, c, d, a, ctx->block[10], 0xbebfbc70, 23)
		MD5_STEP(H5, a, b, c, d, ctx->block[13], 0x289b7ec6, 4)
		MD5_STEP(H5, d, a, b, c, ctx->block[0],  0xeaa127fa, 11)
		MD5_STEP(H5, c, d, a, b, ctx->block[3],  0xd4ef3085, 16)
		MD5_STEP(H5, b, c, d, a, ctx->block[6],  0x04881d05, 23)
		MD5_STEP(H5, a, b, c, d, ctx->block[9],  0xd9d4d039, 4)
		MD5_STEP(H5, d, a, b, c, ctx->block[12], 0xe6db99e5, 11)
		MD5_STEP(H5, c, d, a, b, ctx->block[15], 0x1fa27cf8, 16)
		MD5_STEP(H5, b, c, d, a, ctx->block[2],  0xc4ac5665, 23)
		// Round 4
		MD5_STEP(I5, a, b, c, d, ctx->block[0],  0xf4292244, 6)
		MD5_STEP(I5, d, a, b, c, ctx->block[7],  0x432aff97, 10)
		MD5_STEP(I5, c, d, a, b, ctx->block[14], 0xab9423a7, 15)
		MD5_STEP(I5, b, c, d, a, ctx->block[5],  0xfc93a039, 21)
		MD5_STEP(I5, a, b, c, d, ctx->block[12], 0x655b59c3, 6)
		MD5_STEP(I5, d, a, b, c, ctx->block[3],  0x8f0ccc92, 10)
		MD5_STEP(I5, c, d, a, b, ctx->block[10], 0xffeff47d, 15)
		MD5_STEP(I5, b, c, d, a, ctx->block[1],  0x85845dd1, 21)
		MD5_STEP(I5, a, b, c, d, ctx->block[8],  0x6fa87e4f, 6)
		MD5_STEP(I5, d, a, b, c, ctx->block[15], 0xfe2ce6e0, 10)
		MD5_STEP(I5, c, d, a, b, ctx->block[6],  0xa3014314, 15)
		MD5_STEP(I5, b, c, d, a, ctx->block[13], 0x4e0811a1, 21)
		MD5_STEP(I5, a, b, c, d, ctx->block[4],  0xf7537e82, 6)
		MD5_STEP(I5, d, a, b, c, ctx->block[11], 0xbd3af235, 10)
		MD5_STEP(I5, c, d, a, b, ctx->block[2],  0x2ad7d2bb, 15)
		MD5_STEP(I5, b, c, d, a, ctx->block[9],  0xeb86d391, 21)
		a += saved_a;
		b += saved_b;
		c += saved_c;
		d += saved_d;
		ptr += 64;
	} while(size -= 64);
	ctx->a = a;
	ctx->b = b;
	ctx->c = c;
	ctx->d = d;
	return ptr;
}

/*
 *  Md5Initialise
 *
 *  Initialises an MD5 Context. Use this to initialise/reset a context.
 */
LIBHASH_INLINE_API void Md5Initialise(Md5Context* Context) {
	Context->lo = 0;
	Context->hi = 0;
	Context->a = 0x67452301;
	Context->b = 0xefcdab89;
	Context->c = 0x98badcfe;
	Context->d = 0x10325476;
}

/*
 *  Md5Update
 *
 *  Adds data to the MD5 context. This will process the data and update the internal state of the context. Keep on
 *  calling this function until all the data has been added. Then call Md5Finalise to calculate the hash.
 */
LIBHASH_INLINE_API void Md5Update(Md5Context* Context, const void* Buffer, uint32_t BufferSize) {
	uint32_t  saved_lo, used, free;
	saved_lo = Context->lo;
	if((Context->lo = (saved_lo + BufferSize)&0x1fffffff) < saved_lo) Context->hi++;
	Context->hi += hash_cast(uint32_t, (BufferSize>>29));
	used = saved_lo&0x3f;
	if(used) {
		free = 64 - used;
		if(BufferSize < free) {
			memcpy(&Context->buffer[used], Buffer, BufferSize);
			return;
		}
		memcpy(&Context->buffer[used], Buffer, free);
		Buffer = (uint8_t*)Buffer + free;
		BufferSize -= free;
		Md5TransformFunction(Context, Context->buffer, 64);
	}
	if(BufferSize >= 64) {
		Buffer = Md5TransformFunction(Context, Buffer, BufferSize&~(unsigned long)0x3f);
		BufferSize &= 0x3f;
	}
	memcpy(Context->buffer, Buffer, BufferSize);
}

/*
 *  Md5Finalise
 *
 *  Performs the final calculation of the hash and returns the digest (16 byte buffer containing 128bit hash). After
 *  calling this, Md5Initialised must be used to reuse the context.
 */
LIBHASH_INLINE_API void Md5Finalise(Md5Context* Context, MD5_HASH* Digest) {
	uint32_t used, free;
	used = Context->lo&0x3f;
	Context->buffer[used++] = 0x80;
	free = 64 - used;
	if(free < 8) {
		memset(&Context->buffer[used], 0, free);
		Md5TransformFunction(Context, Context->buffer, 64);
		used = 0;
		free = 64;
	}
	memset(&Context->buffer[used], 0, free - 8);
	Context->lo <<= 3;
	Context->buffer[56] = hash_cast(uint8_t,(Context->lo));
	Context->buffer[57] = hash_cast(uint8_t,(Context->lo >> 8));
	Context->buffer[58] = hash_cast(uint8_t,(Context->lo >> 16));
	Context->buffer[59] = hash_cast(uint8_t,(Context->lo >> 24));
	Context->buffer[60] = hash_cast(uint8_t,(Context->hi));
	Context->buffer[61] = hash_cast(uint8_t,(Context->hi >> 8));
	Context->buffer[62] = hash_cast(uint8_t,(Context->hi >> 16));
	Context->buffer[63] = hash_cast(uint8_t,(Context->hi >> 24));
	Md5TransformFunction(Context, Context->buffer, 64);
	Digest->bytes[0]  = hash_cast(uint8_t,Context->a);
	Digest->bytes[1]  = hash_cast(uint8_t,(Context->a >> 8));
	Digest->bytes[2]  = hash_cast(uint8_t,(Context->a >> 16));
	Digest->bytes[3]  = hash_cast(uint8_t,(Context->a >> 24));
	Digest->bytes[4]  = hash_cast(uint8_t,(Context->b));
	Digest->bytes[5]  = hash_cast(uint8_t,(Context->b >> 8));
	Digest->bytes[6]  = hash_cast(uint8_t,(Context->b >> 16));
	Digest->bytes[7]  = hash_cast(uint8_t,(Context->b >> 24));
	Digest->bytes[8]  = hash_cast(uint8_t,(Context->c));
	Digest->bytes[9]  = hash_cast(uint8_t,(Context->c >> 8));
	Digest->bytes[10] = hash_cast(uint8_t,(Context->c >> 16));
	Digest->bytes[11] = hash_cast(uint8_t,(Context->c >> 24));
	Digest->bytes[12] = hash_cast(uint8_t,(Context->d));
	Digest->bytes[13] = hash_cast(uint8_t,(Context->d >> 8));
	Digest->bytes[14] = hash_cast(uint8_t,(Context->d >> 16));
	Digest->bytes[15] = hash_cast(uint8_t,(Context->d >> 24));
}

/*
 *  Md5Calculate
 *
 *  Combines Md5Initialise, Md5Update, and Md5Finalise into one function. Calculates the MD5 hash of the buffer.
 */
LIBHASH_INLINE_API void Md5Calculate(const void* Buffer, uint32_t BufferSize, MD5_HASH* Digest) {
	Md5Context context;
	Md5Initialise(&context);
	Md5Update(&context, Buffer, BufferSize);
	Md5Finalise(&context, Digest);
}

#undef F5
#undef G5
#undef H5
#undef I5
#undef MD5_STEP
#undef MD5_SET

#ifdef __cplusplus
}
#endif

#endif // __MD5_H__
