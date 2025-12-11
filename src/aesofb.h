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

#ifndef __AESOFB_H__
#define __AESOFB_H__

#include <aes.h>

#define AESOFB_BLOCK_SIZE AES_BLOCK_SIZE

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	AesContext Aes;
	uint8_t CurrentCipherBlock[AESOFB_BLOCK_SIZE];
	uint32_t IndexWithinCipherBlock;
} AesOfbContext;

/*
 *  AesOfbInitialise
 *
 * Initialises an AesOfbContext with an already initialised AesContext and a IV.
 * This function can quickly be used to change the IV without requiring the more
 * lengthy processes of reinitialising an AES key.
 */
LIBHASH_INLINE_API void AesOfbInitialise(AesOfbContext *Context,const AesContext *InitialisedAesContext,
				    const uint8_t IV[AESOFB_BLOCK_SIZE]) {
	Context->Aes = *InitialisedAesContext;
	memcpy(Context->CurrentCipherBlock, IV, sizeof(Context->CurrentCipherBlock));
	Context->IndexWithinCipherBlock = 0;
	AesEncryptInPlace(&Context->Aes, Context->CurrentCipherBlock);
}

/*
 *  AesOfbInitialiseWithKey
 *
 * Initialises an AesOfbContext with an AES Key and an IV. This combines the
 * initialising an AES Context and then running AesOfbInitialise. KeySize must
 * be 16, 24, or 32 (for 128, 192, or 256 bit key size) Returns 0 if successful,
 * or -1 if invalid KeySize provided
 */
LIBHASH_INLINE_API int AesOfbInitialiseWithKey(AesOfbContext *Context,const uint8_t *Key, uint32_t KeySize,
					  const uint8_t IV[AESOFB_BLOCK_SIZE]) {
	AesContext aes;
	if (0 != AesInitialise(&aes, Key, KeySize)) return -1;
	AesOfbInitialise(Context, &aes, IV);
	return 0;
}

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
LIBHASH_INLINE_API void AesOfbXor(AesOfbContext *Context,const void *InBuffer, void *OutBuffer,uint32_t Size) {
	uint32_t amountLeft = Size, outputOffset = 0, chunkSize, amountAvailableInBlock;
	amountAvailableInBlock = AESOFB_BLOCK_SIZE - Context->IndexWithinCipherBlock;
	chunkSize = (((amountAvailableInBlock) < (amountLeft)) ? (amountAvailableInBlock) : (amountLeft));
	XorBuffers(hash_c_cast(uint8_t*,InBuffer), Context->CurrentCipherBlock +
		   (AESOFB_BLOCK_SIZE - amountAvailableInBlock), uhash_cast(uint8_t*,OutBuffer), chunkSize);
	amountLeft -= chunkSize;
	outputOffset += chunkSize;
	Context->IndexWithinCipherBlock += chunkSize;
	while (amountLeft > 0) {
		AesEncryptInPlace(&Context->Aes, Context->CurrentCipherBlock);
		chunkSize = (((amountLeft)<(AESOFB_BLOCK_SIZE))?(amountLeft):(AESOFB_BLOCK_SIZE));
		XorBuffers(	hash_c_cast(uint8_t*,InBuffer)+outputOffset, Context->CurrentCipherBlock,
					(uhash_cast(uint8_t*,OutBuffer)+outputOffset), chunkSize);
		amountLeft -= chunkSize;
		outputOffset += chunkSize;
		Context->IndexWithinCipherBlock = chunkSize; // Note: Not incremented
	}
	if (AESOFB_BLOCK_SIZE == chunkSize) {
		AesEncryptInPlace(&Context->Aes, Context->CurrentCipherBlock);
		Context->IndexWithinCipherBlock = 0;
	}
}

/*
 *  AesOfbOutput
 *
 * Outputs the stream of byte of the AesOfbContext from its current stream
 * position. This will advance the stream index by that number of bytes.
 */
LIBHASH_INLINE_API void AesOfbOutput(AesOfbContext *Context, void *Buffer, uint32_t Size) {
	memset(Buffer, 0, Size);
	AesOfbXor(Context, Buffer, Buffer, Size);
}

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
LIBHASH_INLINE_API int AesOfbXorWithKey(const uint8_t *Key,uint32_t KeySize, const uint8_t IV[AESOFB_BLOCK_SIZE],
				   const void *InBuffer,void *OutBuffer,uint32_t BufferSize) {
	AesOfbContext context;
	int error = AesOfbInitialiseWithKey(&context, Key, KeySize, IV);
	if (error == 0) AesOfbXor(&context, InBuffer, OutBuffer, BufferSize);
	return error;
}

#ifdef __cplusplus
}
#endif

#endif /* __AESOFB_H__ */
