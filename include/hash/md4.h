/**
 * WjCryptLib_Md4
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

#ifndef __MD4I_H__
#define __MD4I_H__

#include <stdint.h>

#define MD4_HASH_SIZE        16
#define MD4_BLOCK_SIZE       64
#define MD4_DIGEST_LENGTH    MD4_HASH_SIZE

typedef struct {
    uint32_t lo;
    uint32_t hi;
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint8_t  buffer[MD4_BLOCK_SIZE];
} Md4Context;

typedef struct {
    uint8_t bytes[MD4_HASH_SIZE];
} MD4_HASH;

#ifdef __cplusplus
extern "C" {
#endif

/*
 *  Md4Initialise
 *
 *  Initialises an MD4 Context. Use this to initialise/reset a context.
 */
extern void Md4Initialise(Md4Context*);

/*
 *  Md4Update
 *
 * Adds data to the MD4 context. This will process the data and update the
 * internal state of the context. Keep on calling this function until all the
 * data has been added. Then call Md4Finalise to calculate the hash.
 */
extern void Md4Update(Md4Context*,const void*,uint32_t);

/*
 *  Md4Finalise
 *
 *  Performs the final calculation of the hash and returns the digest (16 byte
 * buffer containing 128bit hash). After calling this, Md4Initialised must be
 * used to reuse the context.
 */
extern void Md4Finalise(Md4Context*,MD4_HASH*);

/*
 *  Md4Calculate
 *
 *  Combines Md4Initialise, Md4Update, and Md4Finalise into one function.
 * Calculates the MD4 hash of the buffer.
 */
extern void Md4Calculate(const void*,uint32_t,MD4_HASH*);

#ifdef __cplusplus
}
#endif

#endif /* __MD4I_H__ */
