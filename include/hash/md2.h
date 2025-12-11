/**
 * WjCryptLib_Md2
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

#ifndef __MD2I_H__
#define __MD2I_H__

#include <stdint.h>

/* MD2 parameters */
#define MD2_HASH_SIZE    16
#define MD2_BLOCK_SIZE   16
#define MD2_DIGEST_LENGTH MD2_HASH_SIZE

typedef struct {
    uint8_t state[48];
    uint8_t checksum[16];
    uint8_t buffer[MD2_BLOCK_SIZE];
    uint32_t count;
} Md2Context;

typedef struct {
    uint8_t bytes[MD2_HASH_SIZE];
} MD2_HASH;

#ifdef __cplusplus
extern "C" {
#endif

/*
 *  Md2Initialise
 *
 *  Initialises an MD2 Context. Use this to initialise/reset a context.
 */
extern void Md2Initialise(Md2Context*);

/*
 *  Md2Update
 *
 * Adds data to the MD2 context. This will process the data and update the
 * internal state of the context. Keep on calling this function until all the
 * data has been added. Then call Md4Finalise to calculate the hash.
 */
extern void Md2Update(Md2Context*,const void*,uint32_t);

/*
 * Md2Finalise
 *
 * Performs the final calculation of the hash and returns the digest,
 * After calling this, Md4Initialised must be used to reuse the context.
 */
extern void Md2Finalise(Md2Context*,MD2_HASH*);

/*
 *  Md2Calculate
 *
 *  Combines Md2Initialise, Md2Update, and Md2Finalise into one function.
 * Calculates the MD2 hash of the buffer.
 */
extern void Md2Calculate(const void*,uint32_t,MD2_HASH*);

#ifdef __cplusplus
}
#endif

#endif /* __MD2I_H__ */
