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

#ifndef __AESCBCI_H__
#define __AESCBCI_H__

#include <aes.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	AesContext Aes;
	uint8_t PreviousCipherBlock[AES_BLOCK_SIZE];
} AesCbcContext;

/*
 *  XorAesBlock
 *
 *  Takes two source blocks (size AES_BLOCK_SIZE) and XORs them together and
 * puts the result in first block
 */
extern void XorAesBlock(uint8_t*,const uint8_t*);

/*
 *  AesCbcInitialise
 *
 *  Initialises an AesCbcContext with an already initialised AesContext and a
 * IV. This function can quickly be used to change the IV without requiring the
 * more lengthy processes of reinitialising an AES key.
 */
extern void AesCbcInitialise(AesCbcContext*,const AesContext*,const uint8_t[AES_BLOCK_SIZE]);

/*
 *  AesCbcInitialiseWithKey
 *
 *  Initialises an AesCbcContext with an AES Key and an IV. This combines the
 * initialising an AES Context and then running AesCbcInitialise. KeySize must
 * be 16, 24, or 32 (for 128, 192, or 256 bit key size) Returns 0 if successful,
 * or -1 if invalid KeySize provided
 */
extern int AesCbcInitialiseWithKey(AesCbcContext *,const uint8_t*,uint32_t,const uint8_t[AES_BLOCK_SIZE]);

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
extern int AesCbcEncrypt(AesCbcContext*,const void*,void*,uint32_t);

/*
 *  AesCbcDecrypt
 *
 *  Decrypts a buffer of data using an AES CBC context. The data buffer must be
 * a multiple of 16 bytes (128 bits) in size. The "position" of the context will
 * be advanced by the buffer amount. InBuffer and OutBuffer can point to the
 * same location for in-place decrypting. Returns 0 if successful, or -1 if Size
 * is not a multiple of 16 bytes.
 */
extern int AesCbcDecrypt(AesCbcContext*,const void*,void*,uint32_t);

/*
 *  AesCbcEncryptWithKey
 *
 *  This function combines AesCbcInitialiseWithKey and AesCbcEncrypt. This is
 * suitable when encrypting data in one go with a key that is not going to be
 * reused. InBuffer and OutBuffer can point to the same location for inplace
 * encrypting. Returns 0 if successful, or -1 if invalid KeySize provided or
 * BufferSize not a multiple of 16 bytes.
 */
extern int AesCbcEncryptWithKey(const uint8_t*,uint32_t,const uint8_t[AES_BLOCK_SIZE],const void*,void*,uint32_t);

/*
 *  AesCbcDecryptWithKey
 *
 *  This function combines AesCbcInitialiseWithKey and AesCbcDecrypt. This is
 * suitable when decrypting data in one go with a key that is not going to be
 * reused. InBuffer and OutBuffer can point to the same location for inplace
 * decrypting. Returns 0 if successful, or -1 if invalid KeySize provided or
 * BufferSize not a multiple of 16 bytes.
 */
extern int AesCbcDecryptWithKey(const uint8_t*,uint32_t,const uint8_t[AES_BLOCK_SIZE],const void*,void*,uint32_t);

#ifdef __cplusplus
}
#endif

#endif /* __AESCBCI_H__ */
