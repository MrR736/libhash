/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __CRC8_EXT_H__
#define __CRC8_EXT_H__

#include "crc8.h"

#ifdef LIBHASH_USE_FILE
# ifdef LIBHASH_USE_FD
#  ifdef _WIN32
#   include <windows.h>
#   include <fcntl.h>
#   include <io.h>
#  else
#   include <fcntl.h>
#   include <unistd.h>
#  endif
#  ifndef O_BINARY
#   define O_BINARY 0
#  endif
# else
#  include <stdio.h>
# endif
#endif

/*
 * CRC-8 Extended Helper Layer
 *
 * Defines memory and file-based variants for common CRC-8 families.
 *
 * Reflected variants use LSB-first processing.
 * Non-reflected variants use MSB-first processing.
 */

#ifdef __cplusplus
extern "C" {
#endif


LIBHASH_INLINE_API uint8_t cccrc8(
	void (*crc8_table)(uint8_t *table,uint8_t poly),
	uint8_t (*ccrc8t)(uint8_t crc,const void *data,size_t len,const uint8_t *table),
	const void *data,size_t len,uint8_t poly,uint8_t init,uint8_t xorout
) {
	if (!crc8_table || !ccrc8t || !data || len == 0) return 0;
	uint8_t table[256];
	crc8_table(table, poly);
	return (uint8_t)(ccrc8t(init, data, len, table) ^ xorout);
}


/* === Compute CRC-8 over memory === */
#undef __CRC8_FUNCTION__
#define __CRC8_FUNCTION__(tablec, ccrcc, name, poly, init, xorout) \
LIBHASH_INLINE_API uint8_t name(const void *data, size_t len) { \
	if (!data || len == 0) return 0; \
	uint8_t table[256]; \
	tablec(table, (poly)); \
	return (uint8_t)(ccrcc((init), data, len, table) ^ (xorout)); \
}


/* === CRC-8/SMBUS === */
__CRC8_FUNCTION__(crc8_init_table,ccrc8,crc8,CRC8_SMBUS_POLY,CRC8_INIT_0,CRC8_XOR_0)
__CRC8_FUNCTION__(crc8_init_table,ccrc8,crc8_smbus,CRC8_SMBUS_POLY,CRC8_INIT_0,CRC8_XOR_0)

/* === CRC-8/AUTOSAR === */
__CRC8_FUNCTION__(crc8_init_table,ccrc8,crc8_autosar,CRC8_AUTOSAR_POLY,CRC8_INIT_FF,CRC8_XOR_FF)

/* === CRC-8/MAXIM-DOW === */
__CRC8_FUNCTION__(crc8_reflected_table,ccrc8,crc8_maxim,CRC8_MAXIM_POLY_REFLECTED,CRC8_INIT_0,CRC8_XOR_0)
__CRC8_FUNCTION__(crc8_reflected_table,ccrc8,crc8_maxim_dow,CRC8_MAXIM_POLY_REFLECTED,CRC8_INIT_0,CRC8_XOR_0)

/* === CRC-8/ROHC === */
__CRC8_FUNCTION__(crc8_reflected_table,ccrc8,crc8_rohc,CRC8_ROHC_POLY_REFLECTED,CRC8_INIT_FF,CRC8_XOR_0)

/* === CRC-8/WCDMA === */
__CRC8_FUNCTION__(crc8_reflected_table,ccrc8,crc8_wcdma,CRC8_WCDMA_POLY_REFLECTED,CRC8_INIT_0,CRC8_XOR_0)

/* === CRC-8/SAE-J1850 === */
__CRC8_FUNCTION__(crc8_init_table,ccrc8,crc8_sae_j1850,CRC8_SAE_J1850_POLY,CRC8_INIT_FF,CRC8_XOR_FF)

/* === CRC-8/MIFARE-MAD === */
__CRC8_FUNCTION__(crc8_init_table,ccrc8,crc8_mifare_mad,CRC8_MIFARE_MAD_POLY,CRC8_INIT_C7,CRC8_XOR_0)

#undef __CRC8_FUNCTION__


#ifdef LIBHASH_USE_FILE
/* === Compute CRC-8 over file === */
#undef __CRC8_FILE_FUNCTION__
#ifdef LIBHASH_USE_FD
#define __CRC8_FILE_FUNCTION__(ctable, ccrcc, name, poly, init, xorout) \
LIBHASH_INLINE_API uint8_t name##_fd(int fd) { \
	if (fd < 0) return 0; \
	uint8_t table[256]; \
	ctable(table, (poly)); \
	uint8_t crc = (init); \
	uint8_t buf[4096]; \
	ssize_t n; \
	while ((n = read(fd, buf, sizeof(buf))) > 0) \
		crc = ccrcc(crc, buf, (size_t)n, table); \
	if (n < 0) return 0; \
	return (uint8_t)(crc ^ (xorout)); \
} \
LIBHASH_INLINE_API uint8_t name##_file(const char *path) { \
	if (!path) return 0; \
	int fd = open(path, O_RDONLY | O_BINARY); \
	if (fd < 0) return 0; \
	uint8_t crc = name##_fd(fd); \
	close(fd); \
	return crc; \
}
#else
#define __CRC8_FILE_FUNCTION__(ctable, ccrcc, name, poly, init, xorout) \
LIBHASH_INLINE_API uint8_t name##_fp(FILE *fp) { \
	if (!fp) return 0; \
	uint8_t table[256]; \
	ctable(table, (poly)); \
	uint8_t crc = (init); \
	uint8_t buf[4096]; \
	size_t n; \
	while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) \
		crc = ccrcc(crc, buf, n, table); \
	if (ferror(fp)) return 0; \
	return (uint8_t)(crc ^ (xorout)); \
} \
LIBHASH_INLINE_API uint8_t name##_file(const char *path) { \
	if (!path) return 0; \
	FILE *fp = fopen(path, "rb"); \
	if (!fp) return 0; \
	uint8_t crc = name##_fp(fp); \
	fclose(fp); \
	return crc; \
}
#endif /* LIBHASH_USE_FD */

/* === CRC-8/SMBUS === */
__CRC8_FILE_FUNCTION__(crc8_init_table,ccrc8,crc8,CRC8_SMBUS_POLY,CRC8_INIT_0,CRC8_XOR_0)
__CRC8_FILE_FUNCTION__(crc8_init_table,ccrc8,crc8_smbus,CRC8_SMBUS_POLY,CRC8_INIT_0,CRC8_XOR_0)

/* === CRC-8/AUTOSAR === */
__CRC8_FILE_FUNCTION__(crc8_init_table,ccrc8,crc8_autosar,CRC8_AUTOSAR_POLY,CRC8_INIT_FF,CRC8_XOR_FF)

/* === CRC-8/MAXIM-DOW === */
__CRC8_FILE_FUNCTION__(crc8_reflected_table,ccrc8,crc8_maxim,CRC8_MAXIM_POLY_REFLECTED,CRC8_INIT_0,CRC8_XOR_0)
__CRC8_FILE_FUNCTION__(crc8_reflected_table,ccrc8,crc8_maxim_dow,CRC8_MAXIM_POLY_REFLECTED,CRC8_INIT_0,CRC8_XOR_0)

/* === CRC-8/ROHC === */
__CRC8_FILE_FUNCTION__(crc8_reflected_table,ccrc8,crc8_rohc,CRC8_ROHC_POLY_REFLECTED,CRC8_INIT_FF,CRC8_XOR_0)

/* === CRC-8/WCDMA === */
__CRC8_FILE_FUNCTION__(crc8_reflected_table,ccrc8,crc8_wcdma,CRC8_WCDMA_POLY_REFLECTED,CRC8_INIT_0,CRC8_XOR_0)

/* === CRC-8/SAE-J1850 === */
__CRC8_FILE_FUNCTION__(crc8_init_table,ccrc8,crc8_sae_j1850,CRC8_SAE_J1850_POLY,CRC8_INIT_FF,CRC8_XOR_FF)

/* === CRC-8/MIFARE-MAD === */
__CRC8_FILE_FUNCTION__(crc8_init_table,ccrc8,crc8_mifare_mad,CRC8_MIFARE_MAD_POLY,CRC8_INIT_C7,CRC8_XOR_0)

#undef __CRC8_FILE_FUNCTION__
#endif /* LIBHASH_USE_FILE */

#ifdef __cplusplus
}
#endif

#endif /* __CRC8_EXT_H__ */
