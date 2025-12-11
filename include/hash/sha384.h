/*
 * WjCryptLib_Sha256
 *
 * Implementation of SHA256 hash function.
 * Original author: Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 * Modified by WaterJuice retaining Public Domain license.
 *
 * This is free and unencumbered software released into the public domain - June
 * 2013 waterjuice.org
 */

#pragma once

#include <stdint.h>

#define SHA384_BLOCK_SIZE 128
#define SHA384_HASH_SIZE  48

typedef struct {
	uint64_t length_high;   /* high 64 bits of bit length */
	uint64_t length_low;    /* low  64 bits of bit length */
	uint64_t state[8];      /* 8 x 64-bit state words */
	uint32_t curlen;	/* number of bytes currently in buf */
	uint8_t  buf[SHA384_BLOCK_SIZE];
} Sha384Context;

typedef struct {
	uint8_t bytes[SHA384_HASH_SIZE];
} SHA384_HASH;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Sha384Initialise
 *
 * Setup SHA-384 initial values (first 64 bits of sqrt of first primes) per spec.
 */
extern void Sha384Initialise(Sha384Context*);

/*
 * Sha384Update
 *
 * Adds data to the context; processes full 128-byte blocks directly.
 */
extern void Sha384Update(Sha384Context*, const void*,uint32_t);

/*
 * Sha384Finalise
 *
 * Pads, appends 128-bit length, performs final compression and writes 48-byte digest.
 */
extern void Sha384Finalise(Sha384Context*,SHA384_HASH*);

/*
 * Sha384Calculate
 *
 * Combines Sha384Initialise, Sha384Update, and Sha384Finalise into one
 * function. Calculates the SHA384 hash of the buffer.
 */
extern void Sha384Calculate(const void*,uint32_t,SHA384_HASH*);

#ifdef __cplusplus
}
#endif
