/**
 * WjCryptLib_Sha1
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

#ifndef __SHA1_H__
#define __SHA1_H__

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

#define SHA1_BLOCK_SIZE 64
#define SHA1_HASH_SIZE 20

#define S1(value, bits) (((value)<<(bits))|((value)>>(32-(bits))))

// (R0+R1), R2, R3, R4 are the different operations used in SHA1
#if (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)) || \
    (!defined(__WINDOWS__) && (defined(WIN32) || defined(WIN64) || defined(_MSC_VER) || defined(_WIN32)))
#define R0(v,w,x,y,z,i)  z += ((w&(x^y))^y) + (block->l[i] = (S1(block->l[i],24)&0xFF00FF00)|\
	(S1(block->l[i],8)&0x00FF00FF)) + 0x5A827999 + S1(v,5); w=S1(w,30);
#else
#define R0(v,w,x,y,z,i)  z += ((w&(x^y))^y) + block->l[i]+ 0x5A827999 + S1(v,5); w=S1(w,30);
#endif

#define R1(v,w,x,y,z,i)  z += ((w&(x^y))^y) + (block->l[i&15] = S1(block->l[(i+13)&15] ^\
	block->l[(i+8)&15]^block->l[(i+2)&15]^block->l[i&15],1))+ 0x5A827999 + S1(v,5); w=S1(w,30);
#define R2(v,w,x,y,z,i)  z += (w^x^y) + (block->l[i&15] = S1(block->l[(i+13)&15] ^\
	block->l[(i+8)&15]^block->l[(i+2)&15]^block->l[i&15],1))+ 0x6ED9EBA1 + S1(v,5); w=S1(w,30);
#define R3(v,w,x,y,z,i)  z += (((w|x)&y)|(w&x)) + (block->l[i&15] = S1(block->l[(i+13)&15] ^\
	block->l[(i+8)&15]^block->l[(i+2)&15]^block->l[i&15],1))+ 0x8F1BBCDC + S1(v,5); w=S1(w,30);
#define R4(v,w,x,y,z,i)  z += (w^x^y) + (block->l[i&15] = S1(block->l[(i+13)&15] ^\
	block->l[(i+8)&15]^block->l[(i+2)&15]^block->l[i&15],1))+ 0xCA62C1D6 + S1(v,5); w=S1(w,30);

typedef struct {
	uint32_t	State[5];
	uint32_t	Count[2];
	uint8_t		Buffer[SHA1_BLOCK_SIZE];
} Sha1Context;

typedef struct {
	uint8_t	bytes[SHA1_HASH_SIZE];
} SHA1_HASH;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Sha1TransformFunction
 *
 * Hash a single 512-bit block. This is the core of the algorithm
 */
static inline void Sha1TransformFunction(uint32_t state[5], const uint8_t buffer[SHA1_BLOCK_SIZE]) {
	uint32_t a, b, c, d, e;
	uint8_t workspace[SHA1_BLOCK_SIZE];
	typedef union {
		uint8_t  c[SHA1_BLOCK_SIZE];
		uint32_t l[16];
	} CHAR64LONG16;
	CHAR64LONG16* block = uhash_cast(CHAR64LONG16*,workspace);
	memcpy(block->l,buffer,SHA1_BLOCK_SIZE);
	a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];
	// 4 rounds of 20 operations each. Loop unS1led.
	R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
	R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
	R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
	R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
	R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
	R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
	R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
	R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
	R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
	R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
	R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
	R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
	R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
	R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
	R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
	R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
	R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
	R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
	R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
	R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
	// Add the working vars back into context.state[]
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
}

/*
 * Sha1Initialise
 *
 * Initialises an SHA1 Context. Use this to initialise/reset a context.
 */
LIBHASH_INLINE_API void Sha1Initialise(Sha1Context* Context) {
	// SHA1 initialisation constants
	Context->Count[0] = 0;
	Context->Count[1] = 0;
	Context->State[0] = 0x67452301;
	Context->State[1] = 0xEFCDAB89;
	Context->State[2] = 0x98BADCFE;
	Context->State[3] = 0x10325476;
	Context->State[4] = 0xC3D2E1F0;
}

/*
 * Sha1Update
 *
 * Adds data to the SHA1 context.
 * This will process the data and update the internal state of the context. Keep on
 *
 * calling this function until all the data has been added.
 * Then call Sha1Finalise to calculate the hash.
 */
LIBHASH_INLINE_API void Sha1Update(Sha1Context* Context, const void* Buffer, uint32_t BufferSize) {
	uint32_t i, j = (Context->Count[0] >> 3) & 63;
	if((Context->Count[0]+=BufferSize << 3)<(BufferSize<<3)) Context->Count[1]++;
	Context->Count[1]+=(BufferSize >> 29);
	if((j+BufferSize)>63) {
		i = SHA1_BLOCK_SIZE-j;
		memcpy(&Context->Buffer[j],Buffer,i);
		Sha1TransformFunction(Context->State, Context->Buffer);
		for(; i + 63 < BufferSize; i += SHA1_BLOCK_SIZE)
			Sha1TransformFunction(Context->State,uhash_c_cast(uint8_t*,Buffer) + i);
		j = 0;
	} else i = 0;
	memcpy(&Context->Buffer[j], &(uhash_c_cast(uint8_t*,Buffer))[i], BufferSize - i);
}

/*
 * Sha1Finalise
 *
 * Performs the final calculation of the hash and
 * returns the digest (20 byte buffer containing 160bit hash). After
 *
 * calling this, Sha1Initialised must be used to reuse the context.
 */
LIBHASH_INLINE_API void Sha1Finalise(Sha1Context* Context, SHA1_HASH* Digest) {
	uint32_t i;
	uint8_t finalcount[8];
	for(i=0; i<8; i++)
		finalcount[i] = hash_cast(uint8_t,(Context->Count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);
	Sha1Update(Context,uhash_c_cast(uint8_t*,"\x80"),1);
	while((Context->Count[0] & 504)!=448)
		Sha1Update(Context,uhash_c_cast(uint8_t*,"\x0"), 1);
	Sha1Update(Context, finalcount, 8);
	for(i=0; i < SHA1_HASH_SIZE; i++)
		Digest->bytes[i] = hash_cast(uint8_t,(Context->State[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
}

/*
 * Sha1Calculate
 *
 * Combines Sha1Initialise, Sha1Update, and Sha1Finalise into one function.
 * Calculates the SHA1 hash of the buffer.
 */
LIBHASH_INLINE_API void Sha1Calculate(const void* Buffer, uint32_t BufferSize, SHA1_HASH* Digest) {
	Sha1Context context;
	Sha1Initialise(&context);
	Sha1Update(&context, Buffer, BufferSize);
	Sha1Finalise(&context, Digest);
}

#undef R0
#undef R1
#undef R2
#undef R3
#undef R4

#ifdef __cplusplus
}
#endif


#endif /* __SHA1_H__ */
