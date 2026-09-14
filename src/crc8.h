/**
 * WjCryptLib_crc8
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

#ifndef __CRC8_H__
#define __CRC8_H__

#include <stdint.h>
#include <stddef.h>

#if defined(_MSC_VER) && _MSC_VER < 1900 && !defined(inline)
#define inline __inline
#endif

#ifndef LIBHASH_VISIBILITY
#if (defined(__GNUC__) && (__GNUC__ >= 4) && (__GNUC_MINOR__ > 2)) || \
defined(__has_attribute) && __has_attribute(visibility)
#define LIBHASH_VISIBILITY(V) __attribute__ ((visibility (#V)))
#else
#define LIBHASH_VISIBILITY(V)
#endif
#endif

#ifndef LIBHASH_EXPORT
#ifdef _WIN32
#define LIBHASH_EXPORT __declspec(dllexport)
#else
#define LIBHASH_EXPORT LIBHASH_VISIBILITY(default)
#endif
#endif

#ifndef LIBHASH_IMPORT
#ifdef _WIN32
#define LIBHASH_IMPORT __declspec(dllimport)
#else
#define LIBHASH_IMPORT LIBHASH_VISIBILITY(default)
#endif
#endif

#ifndef LIBHASH_INLINE_API
#define LIBHASH_INLINE_API static inline
#endif

#define hash_c_cast(t,p)	((t)(intptr_t)(p))
#define uhash_c_cast(t,p)	((t)(uintptr_t)(p))

#ifdef __cplusplus
#define hash_cast(t,p) static_cast<t>(p)
#define uhash_cast(t,p) reinterpret_cast<t>(p)
#else
#define hash_cast hash_c_cast
#define uhash_cast uhash_c_cast
#endif

/*
 * Common CRC-8 polynomial definitions.
 *
 * Each polynomial is represented in normal (non-reflected) form.
 * Use the reflected form for algorithms that process bits LSB-first.
 *
 * CRC-8/SMBUS
 * CRC-8/AUTOSAR
 * CRC-8/MAXIM-DOW
 * CRC-8/ROHC
 * CRC-8/WCDMA
 * CRC-8/SAE-J1850
 * CRC-8/MIFARE-MAD
 */

#define CRC8_SMBUS_POLY			0x07U
#define CRC8_AUTOSAR_POLY		0x2FU
#define CRC8_MAXIM_POLY			0x31U
#define CRC8_ROHC_POLY			0x07U
#define CRC8_WCDMA_POLY			0x9BU
#define CRC8_SAE_J1850_POLY		0x1DU
#define CRC8_MIFARE_MAD_POLY		0x1DU


/*
 * Reflected polynomial representations.
 *
 * These are the bit-reversed forms of the corresponding
 * normal polynomial representations above.
 */

#define CRC8_SMBUS_POLY_REFLECTED		0xE0U
#define CRC8_AUTOSAR_POLY_REFLECTED		0xF4U
#define CRC8_MAXIM_POLY_REFLECTED		0x8CU
#define CRC8_ROHC_POLY_REFLECTED		0xE0U
#define CRC8_WCDMA_POLY_REFLECTED		0xD9U
#define CRC8_SAE_J1850_POLY_REFLECTED		0xB8U
#define CRC8_MIFARE_MAD_POLY_REFLECTED		0xB8U

#define CRC8_TOPBIT	0x80U
#define CRC8_SHIFT	8U

#define CRC8_INIT_0		0x00U
#define CRC8_INIT_FF	0xFFU
#define CRC8_INIT_C7	0xC7U

#define CRC8_XOR_0		0x00U
#define CRC8_XOR_FF		0xFFU
#define CRC8_XOR_C7		0xC7U

#ifdef __cplusplus
extern "C" {
#endif

LIBHASH_INLINE_API void crc8_reflected_table(uint8_t *table,uint8_t poly) {
	for (unsigned int i = 0; i < 256U; ++i) {
		uint8_t crc = (uint8_t)i;
		for (unsigned int j = 0; j < CRC8_SHIFT; ++j) {
			crc = (uint8_t)((crc >> 1) ^ (poly & (uint8_t)-(crc & 1U)));
		}
		table[i] = crc;
	}
}

LIBHASH_INLINE_API void crc8_init_table(uint8_t *table,uint8_t poly) {
	for (unsigned int i = 0; i < 256U; ++i) {
		uint8_t crc = (uint8_t)i;
		for (unsigned int j = 0; j < CRC8_SHIFT; ++j) {
			crc = (crc & CRC8_TOPBIT) ? (uint8_t)((crc << 1) ^ poly) : (uint8_t)(crc << 1);
		}
		table[i] = crc;
	}
}

LIBHASH_INLINE_API uint8_t ccrc8(uint8_t crc,const void *data,size_t len,const uint8_t *table) {
	const uint8_t *p = uhash_cast(const uint8_t *, data);
	while (len--) crc = table[(crc ^ *p++) & 0xFFU];
	return crc;
}


#ifdef __cplusplus
}
#endif

#endif /* __CRC8_H__ */
