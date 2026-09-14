/**
 * WjCryptLib_crc16
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

#ifndef __CRC16_H__
#define __CRC16_H__

#include <stdint.h>
#include <stddef.h>

#if defined(_MSC_VER) && _MSC_VER < 1900 && !defined(inline)
#define inline __inline
#endif

#ifndef LIBHASH_VISIBILITY
#if (defined(__GNUC__) && (__GNUC__ >= 4) && (__GNUC_MINOR__ > 2)) || __has_attribute(visibility)
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

#define hash_c_cast(t,p)    ((t)(intptr_t)(p))
#define uhash_c_cast(t,p)   ((t)(uintptr_t)(p))

#ifdef __cplusplus
#define hash_cast(t,p) static_cast<t>(p)
#define uhash_cast(t,p) reinterpret_cast<t>(p)
#else
#define hash_cast hash_c_cast
#define uhash_cast uhash_c_cast
#endif


/*
 * Common CRC-16 polynomial definitions.
 *
 * Each polynomial is represented in normal (non-reflected) form.
 * Use the reflected form for algorithms that process bits LSB-first.
 *
 * CRC-16/IBM (ARC)
 * CRC-16/CCITT-FALSE
 * CRC-16/XMODEM
 * CRC-16/MODBUS
 * CRC-16/KERMIT
 * CRC-16/DNP
 * CRC-16/USB
 */

#define CRC16_IBM_POLY		0x8005U
#define CRC16_CCITT_POLY	0x1021U
#define CRC16_XMODEM_POLY	0x1021U
#define CRC16_MODBUS_POLY	0x8005U
#define CRC16_KERMIT_POLY	0x1021U
#define CRC16_DNP_POLY		0x3D65U
#define CRC16_USB_POLY		0x8005U

#define CRC16_IBM_POLY_REFLECTED	0xA001U
#define CRC16_CCITT_POLY_REFLECTED	0x8408U
#define CRC16_XMODEM_POLY_REFLECTED	0x8408U
#define CRC16_MODBUS_POLY_REFLECTED	0xA001U
#define CRC16_KERMIT_POLY_REFLECTED	0x8408U
#define CRC16_DNP_POLY_REFLECTED	0xA6BCU
#define CRC16_USB_POLY_REFLECTED	0xA001U

#define CRC16_TOPBIT	0x8000U
#define CRC16_SHIFT		8

#define CRC16_INIT_0	0x0000U
#define CRC16_INIT_FF	0xFFFFU

#define CRC16_XOR_0		0x0000U
#define CRC16_XOR_FF	0xFFFFU

#ifdef __cplusplus
extern "C" {
#endif

/* Generate CRC-16 lookup table (reflected version). */
LIBHASH_INLINE_API void crc16_reflected_table(uint16_t *table, uint16_t poly) {
	for (uint32_t i = 0; i < 256; ++i) {
		uint16_t crc = (uint16_t)i;
		for (int j = 0; j < 8; ++j) crc = (uint16_t)((crc >> 1) ^ (poly & (uint16_t)-(crc & 1U)));
		table[i] = crc;
	}
}

/* Generate CRC-16 lookup table (non-reflected version). */
LIBHASH_INLINE_API void crc16_init_table(uint16_t *table, uint16_t poly) {
	for (uint32_t i = 0; i < 256; ++i) {
		uint16_t crc = (uint16_t)(i << CRC16_SHIFT);
		for (int j = 0; j < 8; ++j) crc = (crc & CRC16_TOPBIT) ? (uint16_t)((crc << 1) ^ poly) : (uint16_t)(crc << 1);
		table[i] = crc;
	}
}

/* Compute CRC-16 reflected over a byte buffer using precomputed table. */
LIBHASH_INLINE_API uint16_t ccrc16_reflected(uint16_t crc,const void *data,size_t len,const uint16_t *table) {
	const uint8_t *p = uhash_cast(const uint8_t *, data);
	while (len--) crc = (uint16_t)((crc >> 8) ^ table[(crc ^ *p++) & 0xFFU]);
	return crc;
}

/* Compute CRC-16 non-reflected over a byte buffer using precomputed table. */
LIBHASH_INLINE_API uint16_t ccrc16(uint16_t crc,const void *data,size_t len,const uint16_t *table) {
	const uint8_t *p = uhash_cast(const uint8_t *, data);
	while (len--) crc = (uint16_t)((crc << 8) ^ table[((crc >> CRC16_SHIFT) ^ *p++) & 0xFFU]);
	return crc;
}

#ifdef __cplusplus
}
#endif

#endif /* __CRC16_H__ */
