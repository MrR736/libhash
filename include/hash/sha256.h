/**
 * WjCryptLib_Sha256
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

#ifndef __SHA256I_H__
#define __SHA256I_H__

#include <stdint.h>

#define SHA256_BLOCK_SIZE 64
#define SHA256_HASH_SIZE 32

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint64_t	length;
	uint32_t	state[8];
	uint32_t	curlen;
	uint8_t		buf[SHA256_BLOCK_SIZE];
} Sha256Context;

typedef struct {
	uint8_t	bytes[SHA256_HASH_SIZE];
} SHA256_HASH;

/*
 * Sha256Initialise
 *
 * Initialises a SHA256 Context. Use this to initialise/reset a context.
 */
extern void Sha256Initialise(Sha256Context*);

/*
 * Sha256Update
 *
 * Adds data to the SHA256 context. This will process the data and update the
 * internal state of the context. Keep on calling this function until all the
 * data has been added. Then call Sha256Finalise to calculate the hash.
 */
extern void Sha256Update(Sha256Context*, const void*, uint32_t);

/*
 * Sha256Finalise
 *
 * Performs the final calculation of the hash and returns the digest (32 byte
 * buffer containing 256bit hash). After calling this, Sha256Initialised must be
 * used to reuse the context.
 */
extern void Sha256Finalise(Sha256Context*, SHA256_HASH*);

/*
 * Sha256Calculate
 *
 * Combines Sha256Initialise, Sha256Update, and Sha256Finalise into one
 * function. Calculates the SHA256 hash of the buffer.
 */
extern void Sha256Calculate(const void*, uint32_t, SHA256_HASH *);

#ifdef __cplusplus
}
#endif

#endif /* __SHA256I_H__ */
