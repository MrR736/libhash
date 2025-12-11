/*
 *  WjCryptLib_RC4
 *
 *  An implementation of RC4 stream cipher
 *
 *  This is free and unencumbered software released into the public domain - June 2013 waterjuice.org
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint32_t	i;
	uint32_t	j;
	uint8_t		S[256];
} Rc4Context;

/*
 *  Rc4Initialise
 *
 *  Initialises an RC4 cipher and discards the specified number of first bytes.
 */
extern void Rc4Initialise(Rc4Context*,const void*,uint32_t,uint32_t);

/*
 *  Rc4Output
 *
 *  Outputs the requested number of bytes from the RC4 stream
 */
extern void Rc4Output(Rc4Context*,void*,uint32_t);

/*
 *  Rc4Xor
 *
 *  XORs the RC4 stream with an input buffer and puts the results in an output buffer. This is used for encrypting
 *  and decrypting data. InBuffer and OutBuffer can point to the same location for inplace encrypting/decrypting
 */
extern void Rc4Xor(Rc4Context*, const void*, void*, uint32_t);

/*
 * Rc4XorWithKey
 *
 * This function combines Rc4Initialise and Rc4Xor.
 * This is suitable when encrypting/decrypting data in one go with a key that isn't going to be reused.
 * InBuffer and OutBuffer can point to the same location for inplace encrypting/decrypting
 */
extern void Rc4XorWithKey(const uint8_t*,uint32_t,uint32_t,const void*,void*,uint32_t);

#ifdef __cplusplus
}
#endif
