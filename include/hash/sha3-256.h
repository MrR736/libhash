/**
 * WjCryptLib_Sha3_256
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

#ifndef SHA3_256I_H
#define SHA3_256I_H

#include <stdint.h>

#define SHA3_256_BLOCK_SIZE 136
#define SHA3_256_HASH_SIZE  32

typedef struct {
	uint64_t state[25];
	uint32_t curlen;
	uint8_t  buf[SHA3_256_BLOCK_SIZE];
} Sha3_256Context;

typedef struct {
	uint8_t bytes[SHA3_256_HASH_SIZE];
} SHA3_256_HASH;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Sha3_256Initialise
 *
 * Initialises a SHA3-256 Context.
 */
extern void Sha3_256Initialise(Sha3_256Context* Context);

/*
 * Sha3_256Update
 *
 * Adds data to the SHA3-256 context.
 *
 * Data is absorbed in 136-byte blocks.
 */
extern void Sha3_256Update(Sha3_256Context* Context,const void* Buffer,uint32_t BufferSize);

/*
 * Sha3_256Finalise
 *
 * Performs the final SHA3-256 calculation.
 *
 * SHA-3 domain separation:
 *
 *     0x06
 *
 * followed by pad10*1, whose final bit is:
 *
 *     0x80
 */
extern void Sha3_256Finalise(Sha3_256Context* Context,SHA3_256_HASH* Digest);

/*
 * Sha3_256Calculate
 *
 * Combines Sha3_256Initialise, Sha3_256Update,
 * and Sha3_256Finalise into one function.
 */
extern void Sha3_256Calculate(const void* Buffer,uint32_t BufferSize,SHA3_256_HASH* Digest);

#ifdef __cplusplus
}
#endif

#endif /* SHA3_256I_H */
