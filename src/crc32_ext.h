/* SPDX-License-Identifier: GPL-3.0 */
#ifndef __CRC32_EXT_H__
#define __CRC32_EXT_H__

#include "crc32.h"

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
 * CRC-32 Extended Helper Layer
 *
 * Defines memory and file-based variants for all common CRC-32 families.
 * Each uses LSB-first (reflected) processing consistent with IEEE 802.3.
 */

#ifdef __cplusplus
extern "C" {
#endif


LIBHASH_INLINE_API uint32_t cccrc32(
	void (*crc32_table)(uint32_t* table, uint32_t poly),
	uint32_t (*ccrc32t)(uint32_t crc,const void *data,size_t len,const uint32_t* table),
	const void *data, size_t len,uint32_t poly,uint32_t init,uint32_t xorout
) {
	if (!crc32_table || !ccrc32t || !data || len == 0) return 0;
	uint32_t table[256];
	crc32_table(table,poly);
	return ccrc32t(init, data, len, table) ^ xorout;
}

#undef __CRC32_FUNCTION__

/* === Compute CRC-32 over memory === */
#define __CRC32_FUNCTION__(name, poly_reflected) \
LIBHASH_INLINE_API uint32_t name(const void *data, size_t len) { \
	if (!data || len == 0) return 0; \
	uint32_t table[256]; \
	crc32_reflected_table(table, (poly_reflected)); \
	return ccrc32_reflected(0xFFFFFFFFU, data, len, table) ^ 0xFFFFFFFFU; \
}

/* === Standard CRC-32 families === */
__CRC32_FUNCTION__(crc32,CRC32_POLY_REFLECTED)
__CRC32_FUNCTION__(crc32_ieee,CRC32_POLY_REFLECTED)
__CRC32_FUNCTION__(crc32c,CRC32C_POLY_REFLECTED)
__CRC32_FUNCTION__(crc32k,CRC32K_POLY_REFLECTED)
__CRC32_FUNCTION__(crc32q,CRC32Q_POLY_REFLECTED)
__CRC32_FUNCTION__(crc32d,CRC32D_POLY_REFLECTED)
__CRC32_FUNCTION__(crc32_xfer,CRC32_XFER_POLY_REFLECTED)
__CRC32_FUNCTION__(crc32_autosar,CRC32_AUTOSAR_POLY_REFLECTED)

#undef __CRC32_FUNCTION__

#ifdef LIBHASH_USE_FILE
/* === Compute CRC-32 over file === */
#undef __CRC32_FILE_FUNCTION__
#ifdef LIBHASH_USE_FD
#define __CRC32_FILE_FUNCTION__(ctable, ccrcc, name, poly_reflected, init, xorout) \
LIBHASH_INLINE_API uint32_t name##_fd(int fd) { \
	if (fd < 0) return 0; \
	uint32_t table[256]; \
	ctable(table, (poly_reflected)); \
	uint32_t crc = (init); \
	uint8_t buf[4096]; \
	ssize_t n; \
	while ((n = read(fd, buf, sizeof(buf))) > 0) \
		crc = ccrcc(crc, buf, (size_t)n, table); \
	if (n < 0) return 0; \
	return crc ^ (xorout); \
} \
LIBHASH_INLINE_API uint32_t name##_file(const char *path) { \
	if (!path) return 0; \
	int fd = open(path, O_RDONLY | O_BINARY); \
	if (fd < 0) return 0; \
	uint32_t crc = name##_fd(fd); \
	close(fd); \
	return crc; \
}
#else
#define __CRC32_FILE_FUNCTION__(ctable, ccrcc, name, poly_reflected, init, xorout) \
LIBHASH_INLINE_API uint32_t name##_fp(FILE *fp) { \
	if (!fp) return 0; \
	uint32_t table[256]; \
	ctable(table, (poly_reflected)); \
	uint32_t crc = (init); \
	uint8_t buf[4096]; \
	size_t n; \
	while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) \
		crc = ccrcc(crc, buf, n, table); \
	if (ferror(fp)) return 0; \
	return crc ^ (xorout); \
} \
LIBHASH_INLINE_API uint32_t name##_file(const char *path) { \
	if (!path) return 0; \
	FILE *fp = fopen(path, "rb"); \
	if (!fp) return 0; \
	uint32_t crc = name##_fp(fp); \
	fclose(fp); \
	return crc; \
}
#endif

/* === File-based variants === */
__CRC32_FILE_FUNCTION__(crc32_reflected_table,ccrc32_reflected,crc32,CRC32_POLY_REFLECTED,0xFFFFFFFFU,0xFFFFFFFFU)
__CRC32_FILE_FUNCTION__(crc32_reflected_table,ccrc32_reflected,crc32_ieee,CRC32_POLY_REFLECTED,0xFFFFFFFFU,0xFFFFFFFFU)
__CRC32_FILE_FUNCTION__(crc32_reflected_table,ccrc32_reflected,crc32c,CRC32C_POLY_REFLECTED,0xFFFFFFFFU,0xFFFFFFFFU)
__CRC32_FILE_FUNCTION__(crc32_reflected_table,ccrc32_reflected,crc32k,CRC32K_POLY_REFLECTED,0xFFFFFFFFU,0xFFFFFFFFU)
__CRC32_FILE_FUNCTION__(crc32_reflected_table,ccrc32_reflected,crc32q,CRC32Q_POLY_REFLECTED,0xFFFFFFFFU,0xFFFFFFFFU)
__CRC32_FILE_FUNCTION__(crc32_reflected_table,ccrc32_reflected,crc32d,CRC32D_POLY_REFLECTED,0xFFFFFFFFU,0xFFFFFFFFU)
__CRC32_FILE_FUNCTION__(crc32_reflected_table,ccrc32_reflected,crc32_xfer,CRC32_XFER_POLY_REFLECTED,0xFFFFFFFFU,0xFFFFFFFFU)
__CRC32_FILE_FUNCTION__(crc32_reflected_table,ccrc32_reflected,crc32_autosar,CRC32_AUTOSAR_POLY_REFLECTED,0xFFFFFFFFU,0xFFFFFFFFU)
#undef __CRC32_FILE_FUNCTION__
#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRC32_EXT_H__ */
