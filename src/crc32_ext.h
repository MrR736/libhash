/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __CRC32_EXT_H__
#define __CRC32_EXT_H__

#include <stdio.h>
#include <crc32.h>

/*
 * CRC-32 Extended Helper Layer
 *
 * Defines memory and file-based variants for all common CRC-32 families.
 * Each uses LSB-first (reflected) processing consistent with IEEE 802.3.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* === Compute CRC-32 over memory === */
#define __CRC32_FUNCTION__(name, poly_reflected) \
LIBHASH_INLINE_API uint32_t name(const void *data, size_t len) { \
    if (!data || len == 0) \
	return 0; \
    uint32_t table[256]; \
    crc32_reflected_table(table, (poly_reflected)); \
    return ccrc32_reflected(0xFFFFFFFFU, data, len, table) ^ 0xFFFFFFFFU; \
}

/* === Compute CRC-32 over file === */
#define __CRC32_FILE_FUNCTION__(name, poly_reflected) \
LIBHASH_INLINE_API uint32_t name##_file(const char *path) { \
    if (!path) return 0; \
    FILE *fp = fopen(path, "rb"); \
    if (!fp) return 0; \
    uint32_t table[256]; \
    crc32_reflected_table(table, (poly_reflected)); \
    uint32_t crc = 0xFFFFFFFFU; \
    uint8_t buf[4096]; \
    size_t n; \
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) \
	crc = ccrc32_reflected(crc, buf, n, table); \
    fclose(fp); \
    return crc ^ 0xFFFFFFFFU; \
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

/* === File-based variants === */
__CRC32_FILE_FUNCTION__(crc32,CRC32_POLY_REFLECTED)
__CRC32_FILE_FUNCTION__(crc32_ieee,CRC32_POLY_REFLECTED)
__CRC32_FILE_FUNCTION__(crc32c,CRC32C_POLY_REFLECTED)
__CRC32_FILE_FUNCTION__(crc32k,CRC32K_POLY_REFLECTED)
__CRC32_FILE_FUNCTION__(crc32q,CRC32Q_POLY_REFLECTED)
__CRC32_FILE_FUNCTION__(crc32d,CRC32D_POLY_REFLECTED)
__CRC32_FILE_FUNCTION__(crc32_xfer,CRC32_XFER_POLY_REFLECTED)
__CRC32_FILE_FUNCTION__(crc32_autosar,CRC32_AUTOSAR_POLY_REFLECTED)

#undef __CRC32_FUNCTION__
#undef __CRC32_FILE_FUNCTION__

#ifdef __cplusplus
}
#endif

#endif /* __CRC32_EXT_H__ */
