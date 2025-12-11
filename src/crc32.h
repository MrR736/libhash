/**
 * WjCryptLib_crc32
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

#ifndef __CRC32_H__
#define __CRC32_H__

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(_MSC_VER) && _MSC_VER < 1900 && !defined(inline)
#define inline __inline
#endif

#ifndef LIBHASH_VISIBILITY
#if (defined(__GNUC__) &&  (__GNUC__ >= 4) && (__GNUC_MINOR__ > 2)) || __has_attribute(visibility)
#define LIBHASH_VISIBILITY(V) __attribute__ ((visibility (#V)))
#else
#define LIBHASH_VISIBILITY(V)
#endif
#endif

#ifndef LIBHASH_EXPORT
#if defined(WIN32) || defined(WIN64) || defined(_WIN32) || defined(_WIN64)
#define LIBHASH_EXPORT __declspec(dllexport) LIBHASH_VISIBILITY(default)
#else
#define LIBHASH_EXPORT LIBHASH_VISIBILITY(default)
#endif
#endif

#ifndef LIBHASH_IMPORT
#if defined(WIN32) || defined(WIN64) || defined(_WIN32) || defined(_WIN64)
#define LIBHASH_IMPORT __declspec(dllimport) LIBHASH_VISIBILITY(default)
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
 * Common CRC-32 polynomial definitions
 * Each polynomial is represented in normal (non-reflected) form.
 * Use the reflected bit order for algorithms that process bits LSB-first.
 */
#define CRC32_POLY			0x04C11DB7U	/* 1. Default CRC-32 (IEEE 802.3, PKZip, Ethernet, etc.) */
#define CRC32C_POLY			0x1EDC6F41U	/* 2. CRC-32C (Castagnoli, iSCSI, Btrfs, SCTP) */
#define CRC32K_POLY			0x741B8CD7U	/* 3. CRC-32K (Koopman) */
#define CRC32Q_POLY			0x814141ABU	/* 4. CRC-32Q (used in AIXM, aviation industry) */
#define CRC32D_POLY			0xA833982BU	/* 5. CRC-32D (used in disk drive industry) */
#define CRC32_XFER_POLY			0x000000AFU	/* 6. CRC-32XFER (used in XFER, ZMODEM protocols) */
#define CRC32_AUTOSAR_POLY		0xF4ACFB13U	/* 7. CRC-32/AUTOSAR (used in automotive systems) */

#define CRC32_POLY_REFLECTED		0xEDB88320U
#define CRC32C_POLY_REFLECTED		0x82F63B78U
#define CRC32K_POLY_REFLECTED		0xEB31D82EU
#define CRC32Q_POLY_REFLECTED		0xD5828281U
#define CRC32D_POLY_REFLECTED		0xD419CC15U
#define CRC32_XFER_POLY_REFLECTED	0xF5000000U
#define CRC32_AUTOSAR_POLY_REFLECTED	0xC8DF352FU

#define CRC32_TOPBIT	0x80000000U
#define CRC32_SHIFT	24

#ifdef __cplusplus
extern "C" {
#endif

LIBHASH_INLINE_API void crc32_reflected_table(uint32_t* table,uint32_t poly) {
    for (uint32_t i = 0; i < 256; ++i) {
	uint32_t crc = i;
	for (int j = 0; j < 8; ++j)
	    crc = (crc >> 1) ^ (poly & -(crc & 1));
	table[i] = crc;
    }
}

// Generate CRC-32 lookup table (not-reflected version, for byte-wise LSB-first processing)
LIBHASH_INLINE_API void crc32_init_table(uint32_t* table,uint32_t poly) {
    for (uint32_t i = 0; i < 256; ++i) {
	uint32_t crc = i << CRC32_SHIFT;
	for (int j = 0; j < 8; ++j)
	    crc = (crc & CRC32_TOPBIT) ? ((crc << 1) ^ poly) : (crc << 1);
	table[i] = crc;
    }
}

// Compute CRC-32 reflected over a byte buffer using precomputed table
LIBHASH_INLINE_API uint32_t ccrc32_reflected(uint32_t crc, const void *data,size_t len,const uint32_t* table) {
    const uint8_t *p = uhash_cast(const uint8_t*,data);
    while (len--)
	crc = (crc >> 8) ^ table[(crc ^ *p++) & 0xFFU];
    return crc;
}

// Compute CRC-32 not-reflected over a byte buffer using precomputed table
LIBHASH_INLINE_API uint32_t ccrc32(uint32_t crc, const void *data,size_t len,const uint32_t* table) {
    const uint8_t *p = uhash_cast(const uint8_t*,data);
    while (len--)
	crc = (crc >> 8) ^ table[((crc >> CRC32_SHIFT) ^ *p++) & 0xFFU];
    return crc;
}

#ifdef __cplusplus
}
#endif

#endif	/* __CRC32_H__ */
