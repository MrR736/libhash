/**
 * WjCryptLib_Sha3_512
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

#ifndef __SHA3_512_H__
#define __SHA3_512_H__

#include <stdint.h>
#include <memory.h>

#define SHA3_512_BLOCK_SIZE 72
#define SHA3_512_HASH_SIZE  64

typedef struct {
	uint64_t state[25];
	uint32_t curlen;
	uint8_t  buf[SHA3_512_BLOCK_SIZE];
} Sha3_512Context;

typedef struct {
	uint8_t bytes[SHA3_512_HASH_SIZE];
} SHA3_512_HASH;


#ifdef __cplusplus
extern "C" {
#endif

/*
 * Sha3_512Initialise
 *
 * Initialises a SHA3-512 context.
 */
extern void Sha3_512Initialise(Sha3_512Context* Context);


/*
 * Sha3_512Update
 *
 * Adds data to the SHA3-512 context.
 *
 * Data is absorbed in 72-byte blocks because SHA3-512 has:
 *
 *     rate = 1600 - 2*512 = 576 bits = 72 bytes
 */
extern void Sha3_512Update(Sha3_512Context* Context,const void* Buffer,uint32_t BufferSize);


/*
 * Sha3_512Finalise
 *
 * Applies SHA-3's domain separation and padding:
 *
 *     0x06 ... 0x80
 *
 * This is the Keccak pad10*1 padding combined with
 * SHA-3's domain separation suffix.
 */
extern void Sha3_512Finalise(Sha3_512Context* Context,SHA3_512_HASH* Digest);

/*
 * Sha3_512Calculate
 *
 * Combines Sha3_512Initialise, Sha3_512Update,
 * and Sha3_512Finalise into one function.
 */
extern void Sha3_512Calculate(const void* Buffer,uint32_t BufferSize,SHA3_512_HASH* Digest);

#ifdef __cplusplus
}
#endif

#endif /* __SHA3_512_H__ */
