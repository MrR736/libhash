/**
 * WjCryptLib_Sha512/224
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

#ifndef SHA512_224I_H
#define SHA512_224I_H

#include <stdint.h>

#define SHA512_224_BLOCK_SIZE 128
#define SHA512_224_HASH_SIZE   28


#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint64_t length;
	uint64_t state[8];
	uint32_t curlen;
	uint8_t buf[SHA512_224_BLOCK_SIZE];
} Sha512_224Context;


typedef struct {
	uint8_t bytes[SHA512_224_HASH_SIZE];
} SHA512_224_HASH;

extern void Sha512_224Initialise(Sha512_224Context* context);

extern void Sha512_224Update(Sha512_224Context* context,const void* input,uint32_t length);

extern void Sha512_224Finalise(Sha512_224Context* context,SHA512_224_HASH* digest);

extern void Sha512_224Calculate(const void* input,uint32_t length,SHA512_224_HASH* digest);


#ifdef __cplusplus
}
#endif

#endif
