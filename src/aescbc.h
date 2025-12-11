/**
 * WjCryptLib_AesCbc
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

#ifndef __AESCBC_H__
#define __AESCBC_H__

#include <aes.h>

#define AESCBC_BLOCK_SIZE AES_BLOCK_SIZE

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	AesContext Aes;
	uint8_t PreviousCipherBlock[AESCBC_BLOCK_SIZE];
} AesCbcContext;

/*
 *  XorAesBlock
 *
 *  Takes two source blocks (size AESCBC_BLOCK_SIZE) and XORs them together and
 * puts the result in first block
 */
LIBHASH_INLINE_API void XorAesBlock(uint8_t *Block1, const uint8_t *Block2) {
	for (uint32_t i=0; i<AESCBC_BLOCK_SIZE; i++) Block1[i]^=Block2[i];
}

/*
 *  AesCbcInitialise
 *
 *  Initialises an AesCbcContext with an already initialised AesContext and a
 * IV. This function can quickly be used to change the IV without requiring the
 * more lengthy processes of reinitialising an AES key.
 */
LIBHASH_INLINE_API void AesCbcInitialise(AesCbcContext *Context,const AesContext *InitialisedAesContext,
				    const uint8_t IV[AESCBC_BLOCK_SIZE]) {
	Context->Aes = *InitialisedAesContext;
	memcpy(Context->PreviousCipherBlock, IV, sizeof(Context->PreviousCipherBlock));
}

/*
 *  AesCbcInitialiseWithKey
 *
 *  Initialises an AesCbcContext with an AES Key and an IV. This combines the
 * initialising an AES Context and then running AesCbcInitialise. KeySize must
 * be 16, 24, or 32 (for 128, 192, or 256 bit key size) Returns 0 if successful,
 * or -1 if invalid KeySize provided
 */
LIBHASH_INLINE_API int AesCbcInitialiseWithKey(AesCbcContext *Context,const uint8_t *Key,uint32_t KeySize,
					  const uint8_t IV[AESCBC_BLOCK_SIZE]) {
	AesContext aes;
	if (AesInitialise(&aes, Key, KeySize) != 0) return -1;
	AesCbcInitialise(Context, &aes, IV);
	return 0;
}

/*
 *  AesCbcEncrypt
 *
 *  Encrypts a buffer of data using an AES CBC context. The data buffer must be
 * a multiple of 16 bytes (128 bits) in size. The "position" of the context will
 * be advanced by the buffer amount. A buffer can be encrypted in one go or in
 * smaller chunks at a time. The result will be the same as long as data is fed
 * into the function in the same order. InBuffer and OutBuffer can point to the
 * same location for in-place encrypting. Returns 0 if successful, or -1 if Size
 * is not a multiple of 16 bytes.
 */
LIBHASH_INLINE_API int AesCbcEncrypt(AesCbcContext *Context, const void *InBuffer,  void *OutBuffer, uint32_t Size) {
	uint32_t numBlocks = Size / AESCBC_BLOCK_SIZE, offset = 0, i;
	if (Size % AESCBC_BLOCK_SIZE != 0) return -1;
	for (i = 0; i<numBlocks; i++) {
		XorAesBlock(Context->PreviousCipherBlock, (uint8_t*)InBuffer + offset);
		AesEncryptInPlace(&Context->Aes, Context->PreviousCipherBlock);
		memcpy(uhash_cast(uint8_t*, OutBuffer)+offset, Context->PreviousCipherBlock, AESCBC_BLOCK_SIZE);
		offset += AESCBC_BLOCK_SIZE;
	}
	return 0;
}

/*
 *  AesCbcDecrypt
 *
 *  Decrypts a buffer of data using an AES CBC context. The data buffer must be
 * a multiple of 16 bytes (128 bits) in size. The "position" of the context will
 * be advanced by the buffer amount. InBuffer and OutBuffer can point to the
 * same location for in-place decrypting. Returns 0 if successful, or -1 if Size
 * is not a multiple of 16 bytes.
 */
LIBHASH_INLINE_API int AesCbcDecrypt(AesCbcContext *Context, const void *InBuffer, void *OutBuffer, uint32_t Size) {
	uint32_t numBlocks = Size/AESCBC_BLOCK_SIZE, offset = 0, i;
	uint8_t previousCipherBlock[AESCBC_BLOCK_SIZE];
	if (0 != Size % AESCBC_BLOCK_SIZE) return -1;
	for (i = 0; i<numBlocks; i++) {
		memcpy(previousCipherBlock, Context->PreviousCipherBlock, AESCBC_BLOCK_SIZE);
		memcpy(Context->PreviousCipherBlock, (uint8_t*)(InBuffer)+offset, AESCBC_BLOCK_SIZE);
		AesDecrypt(&Context->Aes, Context->PreviousCipherBlock, uhash_cast(uint8_t*, OutBuffer)+offset);
		XorAesBlock(uhash_cast(uint8_t*, OutBuffer)+offset, previousCipherBlock);
		offset += AESCBC_BLOCK_SIZE;
	}
	return 0;
}

/*
 *  AesCbcEncryptWithKey
 *
 *  This function combines AesCbcInitialiseWithKey and AesCbcEncrypt. This is
 * suitable when encrypting data in one go with a key that is not going to be
 * reused. InBuffer and OutBuffer can point to the same location for inplace
 * encrypting. Returns 0 if successful, or -1 if invalid KeySize provided or
 * BufferSize not a multiple of 16 bytes.
 */
LIBHASH_INLINE_API int AesCbcEncryptWithKey(const uint8_t *Key, uint32_t KeySize, const uint8_t IV[AESCBC_BLOCK_SIZE],
								const void *InBuffer, void *OutBuffer, uint32_t BufferSize) {
	AesCbcContext context;
	int error = AesCbcInitialiseWithKey(&context, Key, KeySize, IV);
	if (error == 0) error = AesCbcEncrypt(&context, InBuffer, OutBuffer, BufferSize);
	return error;
}

/*
 *  AesCbcDecryptWithKey
 *
 *  This function combines AesCbcInitialiseWithKey and AesCbcDecrypt. This is
 * suitable when decrypting data in one go with a key that is not going to be
 * reused. InBuffer and OutBuffer can point to the same location for inplace
 * decrypting. Returns 0 if successful, or -1 if invalid KeySize provided or
 * BufferSize not a multiple of 16 bytes.
 */
LIBHASH_INLINE_API int AesCbcDecryptWithKey(const uint8_t *Key, uint32_t KeySize, const uint8_t IV[AESCBC_BLOCK_SIZE],
								const void *InBuffer, void *OutBuffer, uint32_t BufferSize) {
	AesCbcContext context;
	int error = AesCbcInitialiseWithKey(&context, Key, KeySize, IV);
	if (error == 0) error = AesCbcDecrypt(&context, InBuffer, OutBuffer, BufferSize);
	return error;
}

#ifdef __cplusplus
}
#endif

#endif /* __AESCBC_H__ */
