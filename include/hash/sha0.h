/**
 * WjCryptLib_Sha0
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

#ifndef SHA0I_H
#define SHA0I_H

#include <stdint.h>

#define SHA0_BLOCK_SIZE 64
#define SHA0_HASH_SIZE 20

typedef struct {
	uint32_t	State[5];
	uint32_t	Count[2];
	uint8_t		Buffer[SHA0_BLOCK_SIZE];
} Sha0Context;

typedef struct {
	uint8_t	bytes[SHA0_HASH_SIZE];
} SHA0_HASH;


#ifdef __cplusplus
extern "C" {
#endif

/*
 * Sha0Initialise
 *
 * Initialises an SHA-0 Context.
 * Use this to initialise/reset a context.
 */
extern void Sha0Initialise(Sha0Context* Context);

/*
 * Sha0Update
 *
 * Adds data to the SHA-0 context.
 */
extern void Sha0Update(Sha0Context* Context,const void* Buffer,uint32_t BufferSize);

/*
 * Sha0Finalise
 *
 * Performs the final calculation of the hash and
 * returns the digest (20 byte buffer containing the 160-bit hash).
 *
 * After calling this, Sha0Initialise must be used to reuse the context.
 */
extern void Sha0Finalise(Sha0Context* Context,SHA0_HASH* Digest);

/*
 * Sha0Calculate
 *
 * Combines Sha0Initialise, Sha0Update, and Sha0Finalise
 * into one function.
 */
extern void Sha0Calculate(const void* Buffer,uint32_t BufferSize,SHA0_HASH* Digest);


#ifdef __cplusplus
}
#endif

#endif /* __SHA0_H__ */
