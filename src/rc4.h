/*
 *  WjCryptLib_RC4
 *
 *  An implementation of RC4 stream cipher
 *
 *  This is free and unencumbered software released into the public domain -
 * June 2013 waterjuice.org
 */

#pragma once

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

typedef struct {
	uint32_t i;
	uint32_t j;
	uint8_t  S[256];
} Rc4Context;

#ifdef __cplusplus
extern "C" {
#endif

/*
 *  Rc4Initialise
 *
 *  Initialises an RC4 cipher and discards the specified number of first bytes.
 */
LIBHASH_INLINE_API void Rc4Initialise(Rc4Context *Context,const void *Key,uint32_t KeySize,uint32_t DropN) {
	uint32_t i, j, n;
	uint8_t temp;
	for (i = 0; i<256; i++) Context->S[i] = hash_cast(uint8_t,i);
	j = 0;
	for (i = 0; i<256; i++) {
		j = (j+Context->S[i]+(hash_c_cast(uint8_t*,Key))[i%KeySize])%256;
		temp = Context->S[i];
		Context->S[i] = Context->S[j];
		Context->S[j] = temp;
	}
	i = 0;
	j = 0;
	for (n = 0; n<DropN; n++) {
		i = (i+1)%256;
		j = (j+Context->S[i])%256;
		temp = Context->S[i];
		Context->S[i] = Context->S[j];
		Context->S[j] = temp;
	}
	Context->i = i;
	Context->j = j;
}

/*
 *  Rc4Output
 *
 *  Outputs the requested number of bytes from the RC4 stream
 */
LIBHASH_INLINE_API void Rc4Output(Rc4Context *Context, void *Buffer, uint32_t Size) {
	uint32_t n;
	uint8_t temp;
	for (n = 0; n < Size; n++) {
		Context->i = (Context->i+1)%256;
		Context->j = (Context->j+Context->S[Context->i])%256;
		temp = Context->S[Context->i];
		Context->S[Context->i] = Context->S[Context->j];
		Context->S[Context->j] = temp;
		uhash_c_cast(uint8_t*,Buffer)[n] = Context->S[(Context->S[Context->i]+Context->S[Context->j])%256];
	}
}

/*
 *  Rc4Xor
 *
 *  XORs the RC4 stream with an input buffer and puts the results in an output
 * buffer. This is used for encrypting and decrypting data. InBuffer and
 * OutBuffer can point to the same location for inplace encrypting/decrypting
 */
LIBHASH_INLINE_API void Rc4Xor(Rc4Context *Context, const void *InBuffer, void *OutBuffer, uint32_t Size) {
	uint32_t n;
	uint8_t temp;
	for (n = 0; n < Size; n++) {
		Context->i = (Context->i+1)%256;
		Context->j = (Context->j+Context->S[Context->i])%256;
		temp = Context->S[Context->i];
		Context->S[Context->i] = Context->S[Context->j];
		Context->S[Context->j] = temp;
		uhash_c_cast(uint8_t*, OutBuffer)[n] = (hash_c_cast(uint8_t*,InBuffer))[n]^
			     (Context->S[(Context->S[Context->i]+Context->S[Context->j])%256]);
	}
}

/*
 * Rc4XorWithKey
 *
 * This function combines Rc4Initialise and Rc4Xor.
 * This is suitable when encrypting/decrypting data in one go with a key that
 * isn't going to be reused. InBuffer and OutBuffer can point to the same
 * location for inplace encrypting/decrypting
 */
LIBHASH_INLINE_API void Rc4XorWithKey(const uint8_t *Key,uint32_t KeySize,uint32_t DropN,
				      const void *InBuffer,void *OutBuffer,uint32_t BufferSize) {
	Rc4Context context;
	Rc4Initialise(&context, Key, KeySize, DropN);
	Rc4Xor(&context, InBuffer, OutBuffer, BufferSize);
}

#ifdef __cplusplus
}
#endif
