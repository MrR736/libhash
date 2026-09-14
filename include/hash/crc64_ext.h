/**
 * @file crc64_ext.h
 * @brief Extended CRC-64 checksum helper interface.
 *
 * Provides standardized CRC-64 variants for both memory and file sources.
 * Each variant computes a reflected (LSB-first) CRC, consistent with ECMA-182.
 *
 * Variants supported:
 *   - crc64()          : CRC-64/ECMA-182
 *   - crc64_ecma()     : CRC-64/ECMA-182
 *   - crc64_we()       : CRC-64/WE
 *   - crc64_xz()       : CRC-64/XZ
 *   - crc64_iso()      : CRC-64/ISO
 *
 * For each memory variant, a file-based counterpart exists, suffixed with `_file`.
 * Example:
 *     uint64_t a = crc64(data, len);
 *     uint64_t b = crc64_file("example.bin");
 */

#ifndef __CRC64_EXT_H__
#define __CRC64_EXT_H__

#include "crc64.h"

#ifdef __cplusplus
extern "C" {
#endif

extern uint64_t cccrc64(
	void (*crc64_table)(uint64_t* table, uint64_t poly),
	uint64_t (*ccrc64t)(uint64_t crc,const void *data,size_t len,const uint64_t* table),
	const void *data, size_t len,uint64_t poly,uint64_t init,uint64_t xorout
);

/* === Memory-based CRC64 variants === */
extern uint64_t crc64(const void *data, size_t len);
extern uint64_t crc64_ecma(const void *data, size_t len);
extern uint64_t crc64_we(const void *data, size_t len);
extern uint64_t crc64_xz(const void *data, size_t len);
extern uint64_t crc64_iso(const void *data, size_t len);

#ifdef LIBHASH_USE_FILE
/* === File-based CRC64 variants === */
extern uint64_t crc64_file(const char *path);
extern uint64_t crc64_ecma_file(const char *path);
extern uint64_t crc64_we_file(const char *path);
extern uint64_t crc64_xz_file(const char *path);
extern uint64_t crc64_iso_file(const char *path);
#ifdef LIBHASH_USE_FD
extern uint64_t crc64_fd(int fd);
extern uint64_t crc64_ecma_fd(int fd);
extern uint64_t crc64_we_fd(int fd);
extern uint64_t crc64_xz_fd(int fd);
extern uint64_t crc64_iso_fd(int fd);
#else
#include <stdio.h>
extern uint64_t crc64_fp(FILE *fp);
extern uint64_t crc64_ecma_fp(FILE *fp);
extern uint64_t crc64_we_fp(FILE *fp);
extern uint64_t crc64_xz_fp(FILE *fp);
extern uint64_t crc64_iso_fp(FILE *fp);
#endif
#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRC64_EXT_H__ */
