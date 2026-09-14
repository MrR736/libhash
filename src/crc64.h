/**
 * WjCryptLib_crc64
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

#ifndef __CRC64_H__
#define __CRC64_H__

#include <stdint.h>
#include <stddef.h>
#include <memory.h>

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

/*
 * Generate a reflected CRC-64 lookup table.
 *
 * The polynomial must be supplied in reflected form.
 */
LIBHASH_INLINE_API void crc64_reflected_table(uint64_t* table, uint64_t poly) {
	for (uint32_t i = 0; i < 256; ++i) {
		uint64_t crc = (uint64_t)i;
		for (int j = 0; j < 8; ++j) crc = (crc >> 1) ^ (poly & -(crc & 1ULL));
		table[i] = crc;
	}
}

/*
 * Generate a non-reflected CRC-64 lookup table.
 *
 * The polynomial must be supplied in normal form.
 */
LIBHASH_INLINE_API void crc64_init_table(uint64_t* table, uint64_t poly) {
	for (uint32_t i = 0; i < 256; ++i) {
		uint64_t crc = (uint64_t)i << CRC64_SHIFT;
		for (int j = 0; j < 8; ++j) crc = (crc & CRC64_TOPBIT) ? ((crc << 1) ^ poly) : (crc << 1);
		table[i] = crc;
	}
}

/*
 * Compute reflected CRC-64 over a byte buffer using a
 * precomputed reflected lookup table.
 */
LIBHASH_INLINE_API uint64_t ccrc64_reflected(uint64_t crc,const void *data,size_t len,const uint64_t* table) {
	const uint8_t *p = uhash_cast(const uint8_t*, data);
	while (len--) crc = (crc >> 8) ^ table[(crc ^ *p++) & 0xFFULL];
	return crc;
}

/*
 * Compute non-reflected CRC-64 over a byte buffer using a
 * precomputed non-reflected lookup table.
 */
LIBHASH_INLINE_API uint64_t ccrc64(uint64_t crc,const void *data,size_t len,const uint64_t* table) {
	const uint8_t *p = uhash_cast(const uint8_t*, data);
	while (len--) crc = (crc << 8) ^ table[((crc >> CRC64_SHIFT) ^ *p++) & 0xFFULL];
	return crc;
}

#ifdef __cplusplus
}
#endif

#endif /* __CRC64_H__ */
