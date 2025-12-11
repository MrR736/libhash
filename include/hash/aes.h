/**
 * WjCryptLib_Aes
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

#ifndef __AES_H__
#define __AES_H__

#include <stdint.h>

#define AES_KEY_SIZE_128	16
#define AES_KEY_SIZE_192	24
#define AES_KEY_SIZE_256	32
#define AES_BLOCK_SIZE		16

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	unsigned int  eK[60];
	unsigned int  dK[60];
	unsigned long Nr;
} AesContext;

/*
 *  XorBuffer
 *
 * Takes two Source buffers and XORs them together and puts the result in
 * DestinationBuffer
 */
extern void XorBuffers(const uint8_t*,const uint8_t*,uint8_t *,uint32_t);

/*
 *  AesInitialise
 *
 *  Initialises an AesContext with an AES Key. KeySize must be 16, 24, or 32
 * (for 128, 192, or 256 bit key size) Returns 0 if successful, or -1 if invalid
 * KeySize provided
 */
extern int AesInitialise(AesContext*, const void*, uint32_t);

/*
 *  AesEncrypt
 *
 *  Performs an AES encryption of one block (128 bits) with the AesContext
 * initialised with one of the functions AesInitialise[n]. Input and Output can
 * point to same memory location, however it is more efficient to use
 *  AesEncryptInPlace in this situation.
 */
extern void AesEncrypt(const AesContext*,const uint8_t[AES_BLOCK_SIZE],uint8_t[AES_BLOCK_SIZE]);

/*
 *  AesDecrypt
 *
 *  Performs an AES decryption of one block (128 bits) with the AesContext
 * initialised with one of the functions AesInitialise[n]. Input and Output can
 * point to same memory location, however it is more efficient to use
 *  AesDecryptInPlace in this situation.
 */
extern void AesDecrypt(const AesContext*,const uint8_t[AES_BLOCK_SIZE],uint8_t[AES_BLOCK_SIZE]);

/*
 *  AesEncryptInPlace
 *
 *  Performs an AES encryption of one block (128 bits) with the AesContext
 * initialised with one of the functions AesInitialise[n]. The encryption is
 * performed in place.
 */
extern void AesEncryptInPlace(const AesContext*,uint8_t[AES_BLOCK_SIZE]);

/*
 *  AesDecryptInPlace
 *
 *  Performs an AES decryption of one block (128 bits) with the AesContext
 * initialised with one of the functions AesInitialise[n]. The decryption is
 * performed in place.
 */
extern void AesDecryptInPlace(const AesContext*,uint8_t[AES_BLOCK_SIZE]);

#ifdef __cplusplus
}
#endif

#endif // __AES_H__
