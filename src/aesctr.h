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

#ifndef __AESCTR_H__
#define __AESCTR_H__

#include <aes.h>

#define AESCTR_BLOCK_SIZE AES_BLOCK_SIZE
#define AES_CTR_IV_SIZE 8

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	AesContext Aes;
	uint8_t IV[AES_CTR_IV_SIZE];
	uint64_t StreamIndex;
	uint64_t CurrentCipherBlockIndex;
	uint8_t CurrentCipherBlock[AESCTR_BLOCK_SIZE];
} AesCtrContext;

/*
 *  CreateCurrentCipherBlock
 *
 * Takes the IV and the counter in the AesCtrContext and produces the cipher
 * block (CurrentCipherBlock). The cipher block is produced by first creating a
 * 128 bit block with the IV as first 64 bits and the CurrentCipherBlockIndex
 * stored as the remaining 64bits in Network byte order (Big Endian)
 */
static inline void CreateCurrentCipherBlock(AesCtrContext *Context) {
	memcpy(Context->CurrentCipherBlock,Context->IV,AES_CTR_IV_SIZE);
	(Context->CurrentCipherBlock + AES_CTR_IV_SIZE)[0] = hash_cast(uint8_t,(((Context->CurrentCipherBlockIndex) >> 56) & 255));
	(Context->CurrentCipherBlock + AES_CTR_IV_SIZE)[1] = hash_cast(uint8_t,(((Context->CurrentCipherBlockIndex) >> 48) & 255));
	(Context->CurrentCipherBlock + AES_CTR_IV_SIZE)[2] = hash_cast(uint8_t,(((Context->CurrentCipherBlockIndex) >> 40) & 255));
	(Context->CurrentCipherBlock + AES_CTR_IV_SIZE)[3] = hash_cast(uint8_t,(((Context->CurrentCipherBlockIndex) >> 32) & 255));
	(Context->CurrentCipherBlock + AES_CTR_IV_SIZE)[4] = hash_cast(uint8_t,(((Context->CurrentCipherBlockIndex) >> 24) & 255));
	(Context->CurrentCipherBlock + AES_CTR_IV_SIZE)[5] = hash_cast(uint8_t,(((Context->CurrentCipherBlockIndex) >> 16) & 255));
	(Context->CurrentCipherBlock + AES_CTR_IV_SIZE)[6] = hash_cast(uint8_t,(((Context->CurrentCipherBlockIndex) >> 8) & 255));
	(Context->CurrentCipherBlock + AES_CTR_IV_SIZE)[7] = hash_cast(uint8_t,((Context->CurrentCipherBlockIndex) & 255));
	AesEncryptInPlace(&Context->Aes,Context->CurrentCipherBlock);
}

/*
 *  AesCtrInitialise
 *
 * Initialises an AesCtrContext with an already initialised AesContext and a IV.
 * This function can quickly be used to change the IV without requiring the more
 * length processes of reinitialising an AES key.
 */
LIBHASH_INLINE_API void AesCtrInitialise(AesCtrContext *Context,const AesContext *InitialisedAesContext,
				    const uint8_t IV[AES_CTR_IV_SIZE]) {
	Context->Aes = *InitialisedAesContext;
	memcpy(Context->IV, IV, AES_CTR_IV_SIZE);
	Context->StreamIndex = 0;
	Context->CurrentCipherBlockIndex = 0;
	CreateCurrentCipherBlock(Context);
}

/*
 *  AesCtrInitialiseWithKey
 *
 * Initialises an AesCtrContext with an AES Key and an IV. This combines the
 * initialising an AES Context and then running AesCtrInitialise. KeySize must
 * be 16, 24, or 32 (for 128, 192, or 256 bit key size) Returns 0 if successful,
 * or -1 if invalid KeySize provided
 */
LIBHASH_INLINE_API int AesCtrInitialiseWithKey(AesCtrContext *Context,const uint8_t *Key,uint32_t KeySize,
					  const uint8_t IV[AES_CTR_IV_SIZE]) {
	AesContext aes;
	if (AesInitialise(&aes, Key, KeySize) != 0) return -1;
	AesCtrInitialise(Context, &aes, IV);
	return 0;
}

/*
 *  AesCtrSetStreamIndex
 *
 * Sets the current stream index to any arbitrary position. Setting to 0 sets it
 * to the beginning of the stream. Any subsequent output will start from this
 * position
 */
LIBHASH_INLINE_API void AesCtrSetStreamIndex(AesCtrContext *Context, uint64_t StreamIndex) {
	uint64_t blockIndex = StreamIndex / AESCTR_BLOCK_SIZE;
	Context->StreamIndex = StreamIndex;
	if (blockIndex != Context->CurrentCipherBlockIndex) {
		Context->CurrentCipherBlockIndex = blockIndex;
		CreateCurrentCipherBlock(Context);
	}
}

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
LIBHASH_INLINE_API void AesCtrXor(AesCtrContext *Context,const void *InBuffer,void *OutBuffer,uint32_t Size) {
	uint32_t firstChunkSize, amountAvailableInBlock, loopStartingOutputOffset;
	uint64_t loopStartingCipherBlockIndex, cipherBlockIndex = 0;
	uint8_t preCipherBlock[AES_KEY_SIZE_128], encCipherBlock[AES_KEY_SIZE_128];
	int numIterations, i;
	amountAvailableInBlock = AESCTR_BLOCK_SIZE - (Context->StreamIndex % AESCTR_BLOCK_SIZE);
	firstChunkSize = ((amountAvailableInBlock<Size)?amountAvailableInBlock:Size);
	XorBuffers(hash_c_cast(uint8_t*,InBuffer), Context->CurrentCipherBlock +
				(AESCTR_BLOCK_SIZE - amountAvailableInBlock), uhash_cast(uint8_t*,OutBuffer), firstChunkSize);
	numIterations = ((Size - firstChunkSize) + AESCTR_BLOCK_SIZE) / AESCTR_BLOCK_SIZE;
	loopStartingCipherBlockIndex = Context->CurrentCipherBlockIndex + 1;
	loopStartingOutputOffset = firstChunkSize;
	memcpy(preCipherBlock, Context->IV, AES_CTR_IV_SIZE);
#ifdef _OPENMP
#pragma omp parallel for firstprivate(preCipherBlock, cipherBlockIndex) \
	lastprivate(encCipherBlock, cipherBlockIndex)
#endif
	for (i = 0; i < numIterations; i++) {
		uint32_t outputOffset = loopStartingOutputOffset + (AESCTR_BLOCK_SIZE * i);
		uint32_t amountLeft = Size-outputOffset;
		uint32_t chunkSize = ((amountLeft < AESCTR_BLOCK_SIZE) ? amountLeft : AESCTR_BLOCK_SIZE);
		cipherBlockIndex = loopStartingCipherBlockIndex + i;
		(preCipherBlock + AES_CTR_IV_SIZE)[0] = hash_cast(uint8_t,((cipherBlockIndex >> 56) & 255));
		(preCipherBlock + AES_CTR_IV_SIZE)[1] = hash_cast(uint8_t,((cipherBlockIndex >> 48) & 255));
		(preCipherBlock + AES_CTR_IV_SIZE)[2] = hash_cast(uint8_t,((cipherBlockIndex >> 40) & 255));
		(preCipherBlock + AES_CTR_IV_SIZE)[3] = hash_cast(uint8_t,((cipherBlockIndex >> 32) & 255));
		(preCipherBlock + AES_CTR_IV_SIZE)[4] = hash_cast(uint8_t,((cipherBlockIndex >> 24) & 255));
		(preCipherBlock + AES_CTR_IV_SIZE)[5] = hash_cast(uint8_t,((cipherBlockIndex >> 16) & 255));
		(preCipherBlock + AES_CTR_IV_SIZE)[6] = hash_cast(uint8_t,((cipherBlockIndex >> 8) & 255));
		(preCipherBlock + AES_CTR_IV_SIZE)[7] = hash_cast(uint8_t,(cipherBlockIndex & 255));
		AesEncrypt(&Context->Aes, preCipherBlock, encCipherBlock);
		XorBuffers(hash_c_cast(uint8_t*,InBuffer) + outputOffset, encCipherBlock,
				      uhash_cast(uint8_t*,OutBuffer)+outputOffset, chunkSize);
	}
	Context->StreamIndex += Size;
	if (numIterations > 0) {
		Context->CurrentCipherBlockIndex = cipherBlockIndex;
		memcpy(Context->CurrentCipherBlock, encCipherBlock, AESCTR_BLOCK_SIZE);
	}
}

/*
 *  AesCtrOutput
 *
 * Outputs the stream of byte of the AesCtrContext from its current stream
 * position. This will advance the stream index by that number of bytes.
 */
LIBHASH_INLINE_API void AesCtrOutput(AesCtrContext *Context,void *Buffer,uint32_t Size) {
	memset(Buffer, 0, Size);
	AesCtrXor(Context, Buffer, Buffer, Size);
}

/*
 *  AesCtrXorWithKey
 *
 * This function combines AesCtrInitialiseWithKey and AesCtrXor. This is
 * suitable when encrypting/decypting data in one go with a key that is not
 * going to be reused. This will used the provided Key and IV and generate a
 * stream that is XORed over Buffer. Returns 0 if successful, or -1 if invalid
 * KeySize provided
 */
LIBHASH_INLINE_API int AesCtrXorWithKey(const uint8_t *Key,uint32_t KeySize, const uint8_t IV[AES_CTR_IV_SIZE],
				   const void *InBuffer, void *OutBuffer, uint32_t BufferSize) {
	AesCtrContext context;
	int error = AesCtrInitialiseWithKey(&context, Key, KeySize, IV);
	if (error == 0) AesCtrXor(&context, InBuffer, OutBuffer, BufferSize);
	return error;
}

#ifdef __cplusplus
}
#endif

#endif /* __AESCTR_H__ */
