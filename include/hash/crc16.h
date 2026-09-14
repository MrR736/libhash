/**
 * WjCryptLib_crc16
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

#ifndef __CRC16_H__
#define __CRC16_H__

#include <stdint.h>
#include <stddef.h>

/*
 * Common CRC-16 polynomial definitions
 * Each polynomial is represented in normal (non-reflected) form.
 * Use the reflected bit order for algorithms that process bits LSB-first.
 *
 * CRC-16/IBM (ARC)
 * CRC-16/CCITT-FALSE
 * CRC-16/XMODEM
 * CRC-16/MODBUS
 * CRC-16/KERMIT
 * CRC-16/DNP
 * CRC-16/USB
 */
#define CRC16_IBM_POLY		0x8005U	/* 1. CRC-16/IBM, ARC */
#define CRC16_CCITT_POLY	0x1021U	/* 2. CRC-16/CCITT-FALSE */
#define CRC16_XMODEM_POLY	0x1021U	/* 3. CRC-16/XMODEM */
#define CRC16_MODBUS_POLY	0x8005U	/* 4. CRC-16/MODBUS */
#define CRC16_KERMIT_POLY	0x1021U	/* 5. CRC-16/KERMIT */
#define CRC16_DNP_POLY		0x3D65U	/* 6. CRC-16/DNP */
#define CRC16_USB_POLY		0x8005U	/* 7. CRC-16/USB */

#define CRC16_IBM_POLY_REFLECTED	0xA001U
#define CRC16_CCITT_POLY_REFLECTED	0x8408U
#define CRC16_XMODEM_POLY_REFLECTED	0x8408U
#define CRC16_MODBUS_POLY_REFLECTED	0xA001U
#define CRC16_KERMIT_POLY_REFLECTED	0x8408U
#define CRC16_DNP_POLY_REFLECTED	0xA6BCU
#define CRC16_USB_POLY_REFLECTED	0xA001U

#define CRC16_TOPBIT	0x8000U
#define CRC16_SHIFT	8

#define CRC16_INIT_0	0x0000U
#define CRC16_INIT_FF	0xFFFFU

#define CRC16_XOR_0		0x0000U
#define CRC16_XOR_FF	0xFFFFU

#ifdef __cplusplus
extern "C" {
#endif

/* Generate CRC-16 lookup table (reflected version, for byte-wise LSB-first processing) */
extern void crc16_reflected_table(uint16_t*,uint16_t);

/* Generate CRC-16 lookup table (not-reflected version, for byte-wise MSB-first processing) */
extern void crc16_init_table(uint16_t*,uint16_t);

/* Compute CRC-16 reflected over a byte buffer using precomputed table */
extern uint16_t ccrc16_reflected(uint16_t,const void*,size_t,const uint16_t*);

/* Compute CRC-16 not-reflected over a byte buffer using precomputed table */
extern uint16_t ccrc16(uint16_t,const void*,size_t,const uint16_t*);

#ifdef __cplusplus
}
#endif

#endif	// __CRC16_H__
