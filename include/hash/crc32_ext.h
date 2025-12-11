/**
 * @file crc32_ext.h
 * @brief Extended CRC-32 checksum helper interface.
 *
 * Provides standardized CRC-32 variants for both memory and file sources.
 * Each variant computes a reflected (LSB-first) CRC, consistent with IEEE 802.3.
 *
 * Variants supported:
 *   - crc32()          : IEEE 802.3 (Ethernet)
 *   - crc32c()         : Castagnoli polynomial
 *   - crc32k()         : Koopman polynomial
 *   - crc32q()         : Q polynomial (AIXM)
 *   - crc32d()         : SATA polynomial
 *   - crc32_xfer()     : XFER (ZIP-compatible)
 *   - crc32_autosar()  : AUTOSAR standard
 *
 * For each memory variant, a file-based counterpart exists, suffixed with `_file`.
 * Example:
 *     uint32_t a = crc32c(data, len);
 *     uint32_t b = crc32c_file("example.bin");
 */

#ifndef __CRC32_EXT_H__
#define __CRC32_EXT_H__

#include <crc32.h>

#ifdef __cplusplus
extern "C" {
#endif

/* === Memory-based CRC32 variants === */
extern uint32_t crc32(const void *data, size_t len);
extern uint32_t crc32_ieee(const void *data, size_t len);
extern uint32_t crc32c(const void *data, size_t len);
extern uint32_t crc32k(const void *data, size_t len);
extern uint32_t crc32q(const void *data, size_t len);
extern uint32_t crc32d(const void *data, size_t len);
extern uint32_t crc32_xfer(const void *data, size_t len);
extern uint32_t crc32_autosar(const void *data, size_t len);

/* === File-based CRC32 variants === */
extern uint32_t crc32_file(const char *path);
extern uint32_t crc32_ieee_file(const char *path);
extern uint32_t crc32c_file(const char *path);
extern uint32_t crc32k_file(const char *path);
extern uint32_t crc32q_file(const char *path);
extern uint32_t crc32d_file(const char *path);
extern uint32_t crc32_xfer_file(const char *path);
extern uint32_t crc32_autosar_file(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* __CRC32_EXT_H__ */
