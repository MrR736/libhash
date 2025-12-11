/**
 * WjCryptLib_Sha384
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

#ifndef __SHA384_H__
#define __SHA384_H__

#include <stdint.h>
#include <memory.h>
#include <string.h>
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

#define SHA384_BLOCK_SIZE 128
#define SHA384_HASH_SIZE  48

typedef struct {
	uint64_t length_high;
	uint64_t length_low;
	uint64_t state[8];
	uint32_t curlen;
	uint8_t  buf[SHA384_BLOCK_SIZE];
} Sha384Context;

typedef struct {
	uint8_t bytes[SHA384_HASH_SIZE];
} SHA384_HASH;

#ifdef __cplusplus
extern "C" {
#endif

/* 64-bit rotate / shift helpers */
#define ROTR64(x,n) (((x) >> (n)) | ((x) << (64 - (n))))
#define SHR64(x,n)  ((x) >> (n))

#define SIGMA0_64(x) (ROTR64((x),28) ^ ROTR64((x),34) ^ ROTR64((x),39))
#define SIGMA1_64(x) (ROTR64((x),14) ^ ROTR64((x),18) ^ ROTR64((x),41))
#define sigma0_64(x) (ROTR64((x),1)  ^ ROTR64((x),8)  ^ SHR64((x),7))
#define sigma1_64(x) (ROTR64((x),19) ^ ROTR64((x),61) ^ SHR64((x),6))

#define CH64(x,y,z)  ( ((x) & (y)) ^ (~(x) & (z)) )
#define MAJ64(x,y,z) ( ((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)) )

/* SHA-512 constants (first 80) */
static const uint64_t SHA512_K[80] = {
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
 * Sha384TransformFunction
 *
 * Compress 1024-bit block (128 bytes) using SHA-512 core.
 */
static inline void Sha384TransformFunction(Sha384Context* Context, const uint8_t* Buffer) {
    uint64_t S[8], W[80];
    uint64_t t0, t1;
    int i;

    for (i = 0; i < 8; ++i) S[i] = Context->state[i];

    /* Prepare W: read 16 big-endian 64-bit words (8 bytes each) */
    for (i = 0; i < 16; ++i) {
	const uint8_t *q = Buffer + (i * 8);
	W[i] = (hash_cast(uint64_t,q[0]) << 56) | (hash_cast(uint64_t,q[1]) << 48) |
	       (hash_cast(uint64_t,q[2]) << 40) | (hash_cast(uint64_t,q[3]) << 32) |
	       (hash_cast(uint64_t,q[4]) << 24) | (hash_cast(uint64_t,q[5]) << 16) |
	       (hash_cast(uint64_t,q[6]) << 8)  | (hash_cast(uint64_t,q[7]));
    }

    for (i = 16; i < 80; ++i) {
	W[i] = sigma1_64(W[i - 2]) + W[i - 7] + sigma0_64(W[i - 15]) + W[i - 16];
    }

    /* main compression loop */
    for (i = 0; i < 80; ++i) {
	t0 = S[7] + SIGMA1_64(S[4]) + CH64(S[4], S[5], S[6]) + SHA512_K[i] + W[i];
	t1 = SIGMA0_64(S[0]) + MAJ64(S[0], S[1], S[2]);
	S[7] = S[6];
	S[6] = S[5];
	S[5] = S[4];
	S[4] = S[3] + t0;
	S[3] = S[2];
	S[2] = S[1];
	S[1] = S[0];
	S[0] = t0 + t1;
    }

    for (i = 0; i < 8; ++i) Context->state[i] += S[i];
}

/*
 * Sha384Initialise
 *
 * Setup SHA-384 initial values (first 64 bits of sqrt of first primes) per spec.
 */
LIBHASH_INLINE_API void Sha384Initialise(Sha384Context* Context) {
	Context->curlen = 0;
	Context->length_low = 0;
	Context->length_high = 0;
	Context->state[0] = 0xcbbb9d5dc1059ed8ULL;
	Context->state[1] = 0x629a292a367cd507ULL;
	Context->state[2] = 0x9159015a3070dd17ULL;
	Context->state[3] = 0x152fecd8f70e5939ULL;
	Context->state[4] = 0x67332667ffc00b31ULL;
	Context->state[5] = 0x8eb44a8768581511ULL;
	Context->state[6] = 0xdb0c2e0d64f98fa7ULL;
	Context->state[7] = 0x47b5481dbefa4fa4ULL;
}

/*
 * Sha384Update
 *
 * Adds data to the context; processes full 128-byte blocks directly.
 */
LIBHASH_INLINE_API void Sha384Update(Sha384Context* Context, const void* Buffer, uint32_t BufferSize) {
    uint32_t n;
    if (Context->curlen > sizeof(Context->buf)) return;

    while (BufferSize > 0) {
	if (Context->curlen == 0 && BufferSize >= SHA384_BLOCK_SIZE) {
	    Sha384TransformFunction(Context, hash_c_cast(const uint8_t*, Buffer));
	    /* update 128-bit bit-length safely */
	    {
		uint64_t old_low = Context->length_low;
		Context->length_low += (SHA384_BLOCK_SIZE * 8ULL);
		if (Context->length_low < old_low) Context->length_high++;
	    }
	    Buffer = hash_c_cast(const uint8_t*, Buffer) + SHA384_BLOCK_SIZE;
	    BufferSize -= SHA384_BLOCK_SIZE;
	} else {
	    n = ((BufferSize < (SHA384_BLOCK_SIZE - Context->curlen)) ? BufferSize : (SHA384_BLOCK_SIZE - Context->curlen));
	    memcpy(Context->buf + Context->curlen, Buffer, hash_cast(size_t, n));
	    Context->curlen += n;
	    Buffer = hash_c_cast(const uint8_t*, Buffer) + n;
	    BufferSize -= n;
	    if (Context->curlen == SHA384_BLOCK_SIZE) {
		Sha384TransformFunction(Context, Context->buf);
		{
		    uint64_t old_low = Context->length_low;
		    Context->length_low += (SHA384_BLOCK_SIZE * 8ULL);
		    if (Context->length_low < old_low) Context->length_high++;
		}
		Context->curlen = 0;
	    }
	}
    }
}

/*
 * Sha384Finalise
 *
 * Pads, appends 128-bit length, performs final compression and writes 48-byte digest.
 */
LIBHASH_INLINE_API void Sha384Finalise(Sha384Context* Context, SHA384_HASH* Digest) {
    if (Context->curlen >= sizeof(Context->buf)) return;

    /* Save original byte count remaining (before padding) */
    uint32_t orig_curlen = Context->curlen;

    /* Append the '1' bit (0x80) as required by the standard */
    Context->buf[Context->curlen++] = hash_cast(uint8_t, 0x80);

    /* If there's not enough room for the 16-byte length, pad and compress */
    if (Context->curlen > 112) {
        while (Context->curlen < SHA384_BLOCK_SIZE)
            Context->buf[Context->curlen++] = hash_cast(uint8_t, 0);
        Sha384TransformFunction(Context, Context->buf);
        Context->curlen = 0;
    }

    /* Pad remaining bytes with zeros until position 112 */
    while (Context->curlen < 112)
        Context->buf[Context->curlen++] = hash_cast(uint8_t, 0);

    /* Now update the 128-bit bit length using the ORIGINAL remaining bytes (not including padding) */
    {
        uint64_t add_bits = (uint64_t)orig_curlen * 8ULL;
        uint64_t old_low = Context->length_low;
        Context->length_low += add_bits;
        if (Context->length_low < old_low) Context->length_high += 1ULL;
    }

    /* Append the 128-bit length in big-endian order: high 64 then low 64 */
    Context->buf[112] = hash_cast(uint8_t,(Context->length_high >> 56) & 0xFF);
    Context->buf[113] = hash_cast(uint8_t,(Context->length_high >> 48) & 0xFF);
    Context->buf[114] = hash_cast(uint8_t,(Context->length_high >> 40) & 0xFF);
    Context->buf[115] = hash_cast(uint8_t,(Context->length_high >> 32) & 0xFF);
    Context->buf[116] = hash_cast(uint8_t,(Context->length_high >> 24) & 0xFF);
    Context->buf[117] = hash_cast(uint8_t,(Context->length_high >> 16) & 0xFF);
    Context->buf[118] = hash_cast(uint8_t,(Context->length_high >> 8) & 0xFF);
    Context->buf[119] = hash_cast(uint8_t,(Context->length_high >> 0) & 0xFF);

    Context->buf[120] = hash_cast(uint8_t,(Context->length_low >> 56) & 0xFF);
    Context->buf[121] = hash_cast(uint8_t,(Context->length_low >> 48) & 0xFF);
    Context->buf[122] = hash_cast(uint8_t,(Context->length_low >> 40) & 0xFF);
    Context->buf[123] = hash_cast(uint8_t,(Context->length_low >> 32) & 0xFF);
    Context->buf[124] = hash_cast(uint8_t,(Context->length_low >> 24) & 0xFF);
    Context->buf[125] = hash_cast(uint8_t,(Context->length_low >> 16) & 0xFF);
    Context->buf[126] = hash_cast(uint8_t,(Context->length_low >> 8) & 0xFF);
    Context->buf[127] = hash_cast(uint8_t,(Context->length_low >> 0) & 0xFF);

    /* Final compression */
    Sha384TransformFunction(Context, Context->buf);

    /* Output the first 48 bytes (first six 64-bit state words) in big-endian */
    for (int i = 0; i < 6; ++i) {
        uint64_t v = Context->state[i];
        (Digest->bytes + (8 * i))[0] = hash_cast(uint8_t,(v >> 56) & 0xFF);
        (Digest->bytes + (8 * i))[1] = hash_cast(uint8_t,(v >> 48) & 0xFF);
        (Digest->bytes + (8 * i))[2] = hash_cast(uint8_t,(v >> 40) & 0xFF);
        (Digest->bytes + (8 * i))[3] = hash_cast(uint8_t,(v >> 32) & 0xFF);
        (Digest->bytes + (8 * i))[4] = hash_cast(uint8_t,(v >> 24) & 0xFF);
        (Digest->bytes + (8 * i))[5] = hash_cast(uint8_t,(v >> 16) & 0xFF);
        (Digest->bytes + (8 * i))[6] = hash_cast(uint8_t,(v >> 8) & 0xFF);
        (Digest->bytes + (8 * i))[7] = hash_cast(uint8_t,(v >> 0) & 0xFF);
    }

    /* Clear the context for safety */
    memset(Context, 0, sizeof(*Context));
}

/*
 * Sha384Calculate
 *
 * Combines Sha384Initialise, Sha384Update, and Sha384Finalise into one
 * function. Calculates the SHA384 hash of the buffer.
 */
LIBHASH_INLINE_API void Sha384Calculate(const void* Buffer, uint32_t BufferSize, SHA384_HASH* Digest) {
    Sha384Context ctx;
    Sha384Initialise(&ctx);
    Sha384Update(&ctx, Buffer, BufferSize);
    Sha384Finalise(&ctx, Digest);
}

#ifdef __cplusplus
}
#endif

#endif /* __SHA384_H__ */
