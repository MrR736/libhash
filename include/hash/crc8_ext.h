/**
 * @file crc8_ext.h
 * @brief Extended CRC-8 checksum helper interface.
 *
 * Provides standardized CRC-8 variants for both memory and file sources.
 *
 * Reflected variants use LSB-first processing.
 * Non-reflected variants use MSB-first processing.
 *
 * Variants supported:
 *   - crc8()           : CRC-8/SMBUS
 *   - crc8_smbus()     : CRC-8/SMBUS
 *   - crc8_autosar()   : CRC-8/AUTOSAR
 *   - crc8_maxim()     : CRC-8/MAXIM-DOW
 *   - crc8_maxim_dow() : CRC-8/MAXIM-DOW
 *   - crc8_rohc()      : CRC-8/ROHC
 *   - crc8_wcdma()     : CRC-8/WCDMA
 *   - crc8_sae_j1850(): CRC-8/SAE-J1850
 *   - crc8_mifare_mad(): CRC-8/MIFARE-MAD
 *
 * For each memory variant, a file-based counterpart exists, suffixed
 * with `_file`.
 *
 * Example:
 *     uint8_t a = crc8(data, len);
 *     uint8_t b = crc8_file("example.bin");
 */

#ifndef __CRC8_EXT_H__
#define __CRC8_EXT_H__

#include "crc8.h"

#ifdef __cplusplus
extern "C" {
#endif

extern uint8_t cccrc8(
	void (*crc8_table)(uint8_t *table, uint8_t poly),
	uint8_t (*ccrc8t)(
		uint8_t crc,
		const void *data,
		size_t len,
		const uint8_t *table
	),
	const void *data,
	size_t len,
	uint8_t poly,
	uint8_t init,
	uint8_t xorout
);

/* === Memory-based CRC8 variants === */

extern uint8_t crc8(const void *data, size_t len);
extern uint8_t crc8_smbus(const void *data, size_t len);
extern uint8_t crc8_autosar(const void *data, size_t len);
extern uint8_t crc8_maxim(const void *data, size_t len);
extern uint8_t crc8_maxim_dow(const void *data, size_t len);
extern uint8_t crc8_rohc(const void *data, size_t len);
extern uint8_t crc8_wcdma(const void *data, size_t len);
extern uint8_t crc8_sae_j1850(const void *data, size_t len);
extern uint8_t crc8_mifare_mad(const void *data, size_t len);

#ifdef LIBHASH_USE_FILE
/* === File-based CRC8 variants === */
extern uint8_t crc8_file(const char *path);
extern uint8_t crc8_smbus_file(const char *path);
extern uint8_t crc8_autosar_file(const char *path);
extern uint8_t crc8_maxim_file(const char *path);
extern uint8_t crc8_maxim_dow_file(const char *path);
extern uint8_t crc8_rohc_file(const char *path);
extern uint8_t crc8_wcdma_file(const char *path);
extern uint8_t crc8_sae_j1850_file(const char *path);
extern uint8_t crc8_mifare_mad_file(const char *path);

#ifdef LIBHASH_USE_FD
extern uint8_t crc8_fd(int fd);
extern uint8_t crc8_smbus_fd(int fd);
extern uint8_t crc8_autosar_fd(int fd);
extern uint8_t crc8_maxim_fd(int fd);
extern uint8_t crc8_maxim_dow_fd(int fd);
extern uint8_t crc8_rohc_fd(int fd);
extern uint8_t crc8_wcdma_fd(int fd);
extern uint8_t crc8_sae_j1850_fd(int fd);
extern uint8_t crc8_mifare_mad_fd(int fd);
#else
#include <stdio.h>
extern uint8_t crc8_fp(FILE *fp);
extern uint8_t crc8_smbus_fp(FILE *fp);
extern uint8_t crc8_autosar_fp(FILE *fp);
extern uint8_t crc8_maxim_fp(FILE *fp);
extern uint8_t crc8_maxim_dow_fp(FILE *fp);
extern uint8_t crc8_rohc_fp(FILE *fp);
extern uint8_t crc8_wcdma_fp(FILE *fp);
extern uint8_t crc8_sae_j1850_fp(FILE *fp);
extern uint8_t crc8_mifare_mad_fp(FILE *fp);
#endif /* LIBHASH_USE_FD */
#endif /* LIBHASH_USE_FILE */

#ifdef __cplusplus
}
#endif

#endif /* __CRC8_EXT_H__ */
