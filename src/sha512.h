/**
 * WjCryptLib_Sha512
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

#ifndef __SHA512_H__
#define __SHA512_H__

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

#define SHA512_BLOCK_SIZE 128
#define SHA512_HASH_SIZE  64

#define S512(value, bits)  (((value) >> (bits)) | ((value) << (64 - (bits))))
#define Sha512Round(a, b, c, d, e, f, g, h, i) \
	t0 = h + (S512(e, 14) ^ S512(e, 18) ^ S512(e, 41)) + (g^(e&(f^g))) + SHAK512[i] + W[i]; \
	t1 = (S512(a,28)^S512(a,34)^S512(a,39)) + (((a|b)&c)|(a&b)); d += t0; h  = t0 + t1;

typedef struct {
	uint64_t length;
	uint64_t state[8];
	uint32_t curlen;
	uint8_t  buf[SHA512_BLOCK_SIZE];
} Sha512Context;

typedef struct {
	uint8_t bytes[SHA512_HASH_SIZE];
} SHA512_HASH;

#ifdef __cplusplus
extern "C" {
#endif

static const uint64_t SHAK512[80] = {
	0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
	0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
	0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
	0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
	0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
	0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
	0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
	0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
	0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
	0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
	0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
	0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
	0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
	0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
	0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

/*
 *  Sha512TransformFunction
 *
 *  Compress 1024-bits
 */
static inline void Sha512TransformFunction(Sha512Context* Context, const uint8_t* Buffer) {
    uint64_t S[8], W[80], t0, t1;
    int i;
    for(i=0; i<8; i++) { S[i] = Context->state[i]; }
    for(i=0; i<16; i++) {
	W[i] =	(hash_cast(uint64_t,((Buffer+(8*i))[0]&255))<<56)|(hash_cast(uint64_t,((Buffer+(8*i))[1] & 255))<<48)|
		(hash_cast(uint64_t,((Buffer+(8*i))[2]&255))<<40)|(hash_cast(uint64_t,((Buffer+(8*i))[3] & 255))<<32)|
		(hash_cast(uint64_t,((Buffer+(8*i))[4]&255))<<24)|(hash_cast(uint64_t,((Buffer+(8*i))[5] & 255))<<16)|
		(hash_cast(uint64_t,((Buffer+(8*i))[6]&255))<<8) |(hash_cast(uint64_t,((Buffer+(8*i))[7] & 255)));
    }
    for(i=16; i<80; i++) {
	W[i] =	(S512(W[i-2],19)^S512(W[i-2],61)^(((W[i-2])&0xFFFFFFFFFFFFFFFFULL)>>hash_cast(uint64_t,6)))+W[i-7] +
		(S512(W[i-15], 1)^S512(W[i-15], 8)^(((W[i-15])&0xFFFFFFFFFFFFFFFFULL)>>hash_cast(uint64_t,7)))+W[i-16];
    }
    for(i=0; i<80; i+=8) {
	Sha512Round(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],i+0);
	Sha512Round(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],i+1);
	Sha512Round(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],i+2);
	Sha512Round(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],i+3);
	Sha512Round(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],i+4);
	Sha512Round(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],i+5);
	Sha512Round(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],i+6);
	Sha512Round(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],i+7);
    }
    for(i=0; i<8; i++) Context->state[i] = Context->state[i] + S[i];
}

/*
 *  Sha512Initialise
 *
 *  Initialises a SHA512 Context. Use this to initialise/reset a context.
 */
LIBHASH_INLINE_API void Sha512Initialise(Sha512Context* Context) {
	Context->curlen = 0;
	Context->length = 0;
	Context->state[0] = 0x6a09e667f3bcc908ULL;
	Context->state[1] = 0xbb67ae8584caa73bULL;
	Context->state[2] = 0x3c6ef372fe94f82bULL;
	Context->state[3] = 0xa54ff53a5f1d36f1ULL;
	Context->state[4] = 0x510e527fade682d1ULL;
	Context->state[5] = 0x9b05688c2b3e6c1fULL;
	Context->state[6] = 0x1f83d9abfb41bd6bULL;
	Context->state[7] = 0x5be0cd19137e2179ULL;
}

/*
 *  Sha512Update
 *
 *  Adds data to the SHA512 context. This will process the data and update the internal state of the context. Keep on
 *  calling this function until all the data has been added. Then call Sha512Finalise to calculate the hash.
 */
LIBHASH_INLINE_API void Sha512Update(Sha512Context* Context, const void* Buffer, uint32_t BufferSize) {
    uint32_t n;
    if(Context->curlen > sizeof(Context->buf)) return;
    while(BufferSize > 0) {
	if(Context->curlen==0&&BufferSize>=SHA512_BLOCK_SIZE) {
	    Sha512TransformFunction(Context,hash_c_cast(uint8_t*,Buffer));
	    Context->length+=SHA512_BLOCK_SIZE * 8;
	    Buffer=hash_c_cast(uint8_t*,Buffer)+SHA512_BLOCK_SIZE;
	    BufferSize-=SHA512_BLOCK_SIZE;
	} else {
	    n = (((BufferSize)<(SHA512_BLOCK_SIZE - Context->curlen))?(BufferSize):(SHA512_BLOCK_SIZE-Context->curlen));
	    memcpy(Context->buf + Context->curlen, Buffer, hash_cast(size_t,n));
	    Context->curlen += n;
	    Buffer = hash_c_cast(uint8_t*,Buffer)+n;
	    BufferSize -= n;
	    if(Context->curlen == SHA512_BLOCK_SIZE) {
		Sha512TransformFunction(Context, Context->buf);
		Context->length += 8*SHA512_BLOCK_SIZE;
		Context->curlen = 0;
	    }
	}
    }
}

/*
 *  Sha512Finalise
 *
 *  Performs the final calculation of the hash and returns the digest (64 byte buffer containing 512bit hash). After
 *  calling this, Sha512Initialised must be used to reuse the context.
 */
LIBHASH_INLINE_API void Sha512Finalise(Sha512Context* Context, SHA512_HASH* Digest) {
    if (Context->curlen >= sizeof(Context->buf)) return;
    Context->length += Context->curlen * 8ULL;
    Context->buf[Context->curlen++] = hash_cast(uint8_t,0x80);
    if (Context->curlen > 112) {
	while (Context->curlen < SHA512_BLOCK_SIZE) Context->buf[Context->curlen++] = hash_cast(uint8_t,0);
	Sha512TransformFunction(Context, Context->buf);
	Context->curlen = 0;
    }
    while (Context->curlen < 120) Context->buf[Context->curlen++] = hash_cast(uint8_t,0);
    (Context->buf+120)[0] = hash_cast(uint8_t,(((Context->length) >> 56) & 255));
    (Context->buf+120)[1] = hash_cast(uint8_t,(((Context->length) >> 48) & 255));
    (Context->buf+120)[2] = hash_cast(uint8_t,(((Context->length) >> 40) & 255));
    (Context->buf+120)[3] = hash_cast(uint8_t,(((Context->length) >> 32) & 255));
    (Context->buf+120)[4] = hash_cast(uint8_t,(((Context->length) >> 24) & 255));
    (Context->buf+120)[5] = hash_cast(uint8_t,(((Context->length) >> 16) & 255));
    (Context->buf+120)[6] = hash_cast(uint8_t,(((Context->length) >> 8) & 255));
    (Context->buf +120)[7] = hash_cast(uint8_t,((Context->length) & 255));
    Sha512TransformFunction(Context, Context->buf);
    for (int i=0; i<8; i++) {
	(Digest->bytes+(8 * i))[0] = hash_cast(uint8_t,(((Context->state[i]) >> 56) & 255));
	(Digest->bytes+(8 * i))[1] = hash_cast(uint8_t,(((Context->state[i]) >> 48) & 255));
	(Digest->bytes+(8 * i))[2] = hash_cast(uint8_t,(((Context->state[i]) >> 40) & 255));
	(Digest->bytes+(8 * i))[3] = hash_cast(uint8_t,(((Context->state[i]) >> 32) & 255));
	(Digest->bytes+(8 * i))[4] = hash_cast(uint8_t,(((Context->state[i]) >> 24) & 255));
	(Digest->bytes+(8 * i))[5] = hash_cast(uint8_t,(((Context->state[i]) >> 16) & 255));
	(Digest->bytes+(8 * i))[6] = hash_cast(uint8_t,(((Context->state[i]) >> 8) & 255));
	(Digest->bytes+(8 * i))[7] = hash_cast(uint8_t,((Context->state[i]) & 255));
    }
}


/*
 * Sha512Calculate
 *
 * Combines Sha512Initialise, Sha512Update, and Sha512Finalise into one function. Calculates the SHA512 hash of the
 * buffer.
 */
LIBHASH_INLINE_API void Sha512Calculate(const void* Buffer, uint32_t BufferSize, SHA512_HASH* Digest) {
	Sha512Context context;
	Sha512Initialise(&context);
	Sha512Update(&context, Buffer, BufferSize);
	Sha512Finalise(&context, Digest);
}

#ifdef __cplusplus
}
#endif

#endif // __SHA512_H__
