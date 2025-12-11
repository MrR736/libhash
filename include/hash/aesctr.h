/**
 * WjCryptLib_AesCtr
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

#ifndef __AESCTRI_H__
#define __AESCTRI_H__

#include <aes.h>

#define AES_CTR_IV_SIZE 8

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	AesContext Aes;
	uint8_t IV[AES_CTR_IV_SIZE];
	uint64_t StreamIndex;
	uint64_t CurrentCipherBlockIndex;
	uint8_t CurrentCipherBlock[AES_BLOCK_SIZE];
} AesCtrContext;

/*
 *  CreateCurrentCipherBlock
 *
 * Takes the IV and the counter in the AesCtrContext and produces the cipher
 * block (CurrentCipherBlock). The cipher block is produced by first creating a
 * 128 bit block with the IV as first 64 bits and the CurrentCipherBlockIndex
 * stored as the remaining 64bits in Network byte order (Big Endian)
 */
extern void CreateCurrentCipherBlock(AesCtrContext*);

/*
 *  AesCtrInitialise
 *
 * Initialises an AesCtrContext with an already initialised AesContext and a IV.
 * This function can quickly be used to change the IV without requiring the more
 * length processes of reinitialising an AES key.
 */
extern void AesCtrInitialise(AesCtrContext*,const AesContext*,const uint8_t[AES_CTR_IV_SIZE]);

/*
 *  AesCtrInitialiseWithKey
 *
 * Initialises an AesCtrContext with an AES Key and an IV. This combines the
 * initialising an AES Context and then running AesCtrInitialise. KeySize must
 * be 16, 24, or 32 (for 128, 192, or 256 bit key size) Returns 0 if successful,
 * or -1 if invalid KeySize provided
 */
extern int AesCtrInitialiseWithKey(AesCtrContext*,const uint8_t*,uint32_t,const uint8_t[AES_CTR_IV_SIZE]);

/*
 *  AesCtrSetStreamIndex
 *
 * Sets the current stream index to any arbitrary position. Setting to 0 sets it
 * to the beginning of the stream. Any subsequent output will start from this
 * position
 */
extern void AesCtrSetStreamIndex(AesCtrContext*,uint64_t);

/*
 *  AesCtrXor
 *
 * XORs the stream of byte of the AesCtrContext from its current stream position
 * onto the specified buffer. This will advance the stream index by that number
 * of bytes. Use once over data to encrypt it. Use it a second time over the
 * same data from the same stream position and the data will be decrypted.
 * InBuffer and OutBuffer can point to the same location for in-place
 * encrypting/decrypting
 */
extern void AesCtrXor(AesCtrContext*,const void*,void*,uint32_t);

/*
 *  AesCtrOutput
 *
 * Outputs the stream of byte of the AesCtrContext from its current stream
 * position. This will advance the stream index by that number of bytes.
 */
extern void AesCtrOutput(AesCtrContext*,void*,uint32_t);

/*
 *  AesCtrXorWithKey
 *
 * This function combines AesCtrInitialiseWithKey and AesCtrXor. This is
 * suitable when encrypting/decypting data in one go with a key that is not
 * going to be reused. This will used the provided Key and IV and generate a
 * stream that is XORed over Buffer. Returns 0 if successful, or -1 if invalid
 * KeySize provided
 */
extern int AesCtrXorWithKey(const uint8_t*,uint32_t,const uint8_t[AES_CTR_IV_SIZE],const void*,void*,uint32_t);

#ifdef __cplusplus
}
#endif

#endif /* __AESCTRI_H__ */
