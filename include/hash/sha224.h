/**
 * WjCryptLib_Sha224
 *
 * Copyright (C) 2025 MrR736 <MrR736@users.github.com>
 *
 * Original Author: Steve Reid <sreid@sea-to-sky.net>
 * Contributions by: James H. Brown <jbrown@burgoyne.com>, Saul Kravitz <Saul.Kravitz@celera.com>,
 * Ralph Giles <giles@ghostscript.com>
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

#ifndef __SHA224I_H__
#define __SHA224I_H__

#include <stdint.h>

#define SHA224_BLOCK_SIZE 64
#define SHA224_HASH_SIZE  28

typedef struct {
    uint64_t length;
    uint32_t state[8];
    uint32_t curlen;
    uint8_t  buf[SHA224_BLOCK_SIZE];
} Sha224Context;

typedef struct {
    uint8_t bytes[SHA224_HASH_SIZE];
} SHA224_HASH;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Sha224Initialise
 *
 * Initialises a SHA224 Context. Use this to initialise/reset a context.
 */
extern void Sha224Initialise(Sha224Context*);

/*
 * Sha224Update
 *
 * Adds data to the SHA224 context. This will process the data and update the
 * internal state of the context. Keep on calling this function until all the
 * data has been added. Then call Sha224Finalise to calculate the hash.
 */
extern void Sha224Update(Sha224Context*, const void*, uint32_t);

/*
 * Sha224Finalise
 *
 * Performs the final calculation of the hash and returns the digest (32 byte
 * buffer containing 224bit hash). After calling this, Sha224Initialised must be
 * used to reuse the context.
 */
extern void Sha224Finalise(Sha224Context*, SHA224_HASH*);

/*
 * Sha224Calculate
 *
 * Combines Sha224Initialise, Sha224Update, and Sha224Finalise into one
 * function. Calculates the SHA224 hash of the buffer.
 */
extern void Sha224Calculate(const void*, uint32_t, SHA224_HASH *);

#ifdef __cplusplus
}
#endif

#endif /* __SHA224I_H__ */
