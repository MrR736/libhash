/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __CRC32_H__
#define __CRC32_H__

#include <stdint.h>
#include <stddef.h>

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

#define CRC32_SHIFT	24

#ifdef __cplusplus
extern "C" {
#endif

// Generate CRC-32 lookup table (reflected version, for byte-wise LSB-first processing)
extern void crc32_reflected_table(uint32_t*,uint32_t);

// Generate CRC-32 lookup table (not-reflected version, for byte-wise LSB-first processing)
extern void crc32_init_table(uint32_t* table,uint32_t poly);

// Compute CRC-32 reflected over a byte buffer using precomputed table
extern uint32_t ccrc32_reflected(uint32_t,const void*,size_t,const uint32_t*);

// Compute CRC-32 not-reflected over a byte buffer using precomputed table
extern uint32_t ccrc32(uint32_t,const void*,size_t,const uint32_t*);

#ifdef __cplusplus
}
#endif

#endif	// __CRC32_H__
