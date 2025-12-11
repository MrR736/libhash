/**
 * WjCryptLib_AesOfb
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

#ifndef __AESOFBI_H__
#define __AESOFBI_H__

#include <aes.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	AesContext Aes;
	uint8_t CurrentCipherBlock[AES_BLOCK_SIZE];
	uint32_t IndexWithinCipherBlock;
} AesOfbContext;

/*
 *  AesOfbInitialise
 *
 * Initialises an AesOfbContext with an already initialised AesContext and a IV.
 * This function can quickly be used to change the IV without requiring the more
 * lengthy processes of reinitialising an AES key.
 */
extern void AesOfbInitialise(AesOfbContext*,const AesContext*,const uint8_t[AES_BLOCK_SIZE]);

/*
 *  AesOfbInitialiseWithKey
 *
 * Initialises an AesOfbContext with an AES Key and an IV. This combines the
 * initialising an AES Context and then running AesOfbInitialise. KeySize must
 * be 16, 24, or 32 (for 128, 192, or 256 bit key size) Returns 0 if successful,
 * or -1 if invalid KeySize provided
 */
extern int AesOfbInitialiseWithKey(AesOfbContext*,const uint8_t*,uint32_t,const uint8_t[AES_BLOCK_SIZE]);

/*
 *  AesOfbXor
 *
 * XORs the stream of byte of the AesOfbContext from its current stream position
 * onto the specified buffer. This will advance the stream index by that number
 * of bytes. Use once over data to encrypt it. Use it a second time over the
 * same data from the same stream position and the data will be decrypted.
 * InBuffer and OutBuffer can point to the same location for in-place
 * encrypting/decrypting
 */
extern void AesOfbXor(AesOfbContext*,const void*,void*,uint32_t);

/*
 *  AesOfbOutput
 *
 * Outputs the stream of byte of the AesOfbContext from its current stream
 * position. This will advance the stream index by that number of bytes.
 */
extern void AesOfbOutput(AesOfbContext*,void*,uint32_t);

/*
 *  AesOfbXorWithKey
 *
 * This function combines AesOfbInitialiseWithKey and AesOfbXor. This is
 * suitable when encrypting/decypting data in one go with a key that is not
 * going to be reused. This will used the provided Key and IV and generate a
 * stream that is XORed over Buffer. InBuffer and OutBuffer can point to the
 * same location for inplace encrypting/decrypting Returns 0 if successful, or
 * -1 if invalid KeySize provided
 */
extern int AesOfbXorWithKey(const uint8_t*,uint32_t,const uint8_t[AES_BLOCK_SIZE],const void*,void*,uint32_t);

#ifdef __cplusplus
}
#endif

#endif /* __AESOFBI_H__ */
