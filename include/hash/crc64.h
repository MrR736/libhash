/**
 * WjCryptLib_crc64
 *
 * Copyright (C) 2026 MrR736 <MrR736@users.github.com>
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

#ifndef __CRC64_H__
#define __CRC64_H__

#include <stdint.h>
#include <stddef.h>

/*
 * Common CRC-64 polynomial definitions.
 *
 * Polynomials are represented in normal, non-reflected form.
 * Reflected algorithms use the corresponding reflected polynomial.
 */

/* CRC-64/ECMA-182 */
#define CRC64_ECMA_POLY				0x42F0E1EBA9EA3693ULL
#define CRC64_ECMA_POLY_REFLECTED	0xC96C5795D7870F42ULL

/* CRC-64/WE uses the ECMA polynomial. */
#define CRC64_WE_POLY				CRC64_ECMA_POLY
#define CRC64_WE_POLY_REFLECTED		CRC64_ECMA_POLY_REFLECTED

/* CRC-64/XZ uses the ECMA polynomial in reflected form. */
#define CRC64_XZ_POLY				CRC64_ECMA_POLY
#define CRC64_XZ_POLY_REFLECTED		CRC64_ECMA_POLY_REFLECTED

/* CRC-64/ISO */
#define CRC64_ISO_POLY				0x000000000000001BULL
#define CRC64_ISO_POLY_REFLECTED	0xD800000000000000ULL

#define CRC64_TOPBIT	0x8000000000000000ULL
#define CRC64_SHIFT		56

#define CRC64_INIT_0	0x0000000000000000ULL
#define CRC64_INIT_FF	0xFFFFFFFFFFFFFFFFULL

#define CRC64_XOR_0		0x0000000000000000ULL
#define CRC64_XOR_FF	0xFFFFFFFFFFFFFFFFULL

#ifdef __cplusplus
extern "C" {
#endif

// Generate CRC-32 lookup table (reflected version, for byte-wise LSB-first processing)
extern void crc64_reflected_table(uint64_t* table, uint64_t poly);

// Generate CRC-32 lookup table (not-reflected version, for byte-wise LSB-first processing)
extern void crc64_init_table(uint64_t* table, uint64_t poly);

// Compute CRC-32 reflected over a byte buffer using precomputed table
extern uint64_t ccrc64_reflected(uint64_t crc,const void *data,size_t len,const uint64_t* table);

// Compute CRC-32 not-reflected over a byte buffer using precomputed table
extern uint64_t ccrc64(uint64_t crc,const void *data,size_t len,const uint64_t* table);

#ifdef __cplusplus
}
#endif

#endif	// __CRC64_H__
