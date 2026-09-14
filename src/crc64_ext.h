/* SPDX-License-Identifier: GPL-3.0 */
#ifndef __CRC64_EXT_H__
#define __CRC64_EXT_H__

#include "crc64.h"

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
 * CRC-64 Extended Helper Layer
 *
 * Defines memory and file-based variants for all common CRC-64 families.
 * Each uses LSB-first (reflected) processing consistent with IEEE 802.3.
 */

#ifdef __cplusplus
extern "C" {
#endif

LIBHASH_INLINE_API uint64_t cccrc64(
	void (*crc64_table)(uint64_t* table, uint64_t poly),
	uint64_t (*ccrc64t)(uint64_t crc,const void *data,size_t len,const uint64_t* table),
	const void *data, size_t len,uint64_t poly,uint64_t init,uint64_t xorout
) {
	if (!crc64_table || !ccrc64t || !data || len == 0) return 0;
	uint64_t table[256];
	crc64_table(table,poly);
	return ccrc64t(init, data, len, table) ^ xorout;
}

#undef __CRC64_FUNCTION_REFLECTED__
#undef __CRC64_FUNCTION_NORMAL__

// Reflected CRC-64 memory function.
#define __CRC64_FUNCTION_REFLECTED__(name, poly_reflected, init, xorout) \
LIBHASH_INLINE_API uint64_t name(const void *data, size_t len) { \
	if (!data && len != 0) return 0; \
	uint64_t table[256]; \
	crc64_reflected_table(table, (poly_reflected)); \
	return ccrc64_reflected((init), data, len, table) ^ (xorout); \
}

// Non-reflected CRC-64 memory function.
#define __CRC64_FUNCTION_NORMAL__(name, poly, init, xorout) \
LIBHASH_INLINE_API uint64_t name(const void *data, size_t len) { \
	if (!data && len != 0) return 0; \
	uint64_t table[256]; \
	crc64_init_table(table, (poly)); \
	return ccrc64((init), data, len, table) ^ (xorout); \
}

/* === Standard CRC-64 families === */

/* CRC-64/ECMA-182 */
__CRC64_FUNCTION_NORMAL__(crc64,CRC64_ECMA_POLY,CRC64_INIT_0,CRC64_XOR_0)
__CRC64_FUNCTION_NORMAL__(crc64_ecma,CRC64_ECMA_POLY,CRC64_INIT_0,CRC64_XOR_0)

/* CRC-64/WE */
__CRC64_FUNCTION_NORMAL__(crc64_we,CRC64_WE_POLY,CRC64_INIT_FF,CRC64_XOR_FF)

/* CRC-64/XZ */
__CRC64_FUNCTION_REFLECTED__(crc64_xz,CRC64_XZ_POLY_REFLECTED,CRC64_INIT_FF,CRC64_XOR_FF)

/* CRC-64/ISO */
__CRC64_FUNCTION_REFLECTED__(crc64_iso,CRC64_ISO_POLY_REFLECTED,CRC64_INIT_FF,CRC64_XOR_FF)

#undef __CRC64_FUNCTION_REFLECTED__
#undef __CRC64_FUNCTION_NORMAL__

#ifdef LIBHASH_USE_FILE
/* === Compute CRC-64 over file === */
#undef __CRC64_FILE_FUNCTION__
#ifdef LIBHASH_USE_FD

#define __CRC64_FILE_FUNCTION__(ctable, ccrcc, name, poly_reflected, init, xorout) \
LIBHASH_INLINE_API uint64_t name##_fd(int fd) { \
	if (fd < 0) return 0; \
	uint64_t table[256]; \
	ctable(table, (poly_reflected)); \
	uint64_t crc = (init); \
	uint8_t buf[4096]; \
	ssize_t n; \
	while ((n = read(fd, buf, sizeof(buf))) > 0) \
		crc = ccrcc(crc, buf, (size_t)n, table); \
	if (n < 0) return 0; \
	return crc ^ (xorout); \
} \
LIBHASH_INLINE_API uint64_t name##_file(const char *path) { \
	if (!path) return 0; \
	int fd = open(path, O_RDONLY | O_BINARY); \
	if (fd < 0) return 0; \
	uint64_t crc = name##_fd(fd); \
	close(fd); \
	return crc; \
}
#else
#define __CRC64_FILE_FUNCTION__(ctable, ccrcc, name, poly_reflected, init, xorout) \
LIBHASH_INLINE_API uint64_t name##_fp(FILE *fp) { \
	if (!fp) return 0; \
	uint64_t table[256]; \
	ctable(table, (poly_reflected)); \
	uint64_t crc = (init); \
	uint8_t buf[4096]; \
	size_t n; \
	while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) \
		crc = ccrcc(crc, buf, n, table); \
	if (ferror(fp)) return 0; \
	return crc ^ (xorout); \
} \
LIBHASH_INLINE_API uint64_t name##_file(const char *path) { \
	if (!path) return 0; \
	FILE *fp = fopen(path, "rb"); \
	if (!fp) return 0; \
	uint64_t crc = name##_fp(fp); \
	fclose(fp); \
	return crc; \
}
#endif

/* === File-based variants === */
__CRC64_FILE_FUNCTION__(crc64_init_table,ccrc64,crc64,CRC64_ECMA_POLY,CRC64_INIT_0,CRC64_XOR_0)
__CRC64_FILE_FUNCTION__(crc64_init_table,ccrc64,crc64_ecma,CRC64_ECMA_POLY,CRC64_INIT_0,CRC64_XOR_0)
__CRC64_FILE_FUNCTION__(crc64_init_table,ccrc64,crc64_we,CRC64_WE_POLY,CRC64_INIT_FF,CRC64_XOR_FF)
__CRC64_FILE_FUNCTION__(crc64_reflected_table,ccrc64_reflected,crc64_xz,CRC64_XZ_POLY_REFLECTED,CRC64_INIT_FF,CRC64_XOR_FF)
__CRC64_FILE_FUNCTION__(crc64_reflected_table,ccrc64_reflected,crc64_iso,CRC64_ISO_POLY_REFLECTED,CRC64_INIT_FF,CRC64_XOR_FF)
#undef __CRC64_FILE_FUNCTION__
#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRC64_EXT_H__ */
