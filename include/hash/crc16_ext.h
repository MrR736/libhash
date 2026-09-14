/**
 * @file crc16_ext.h
 * @brief Extended CRC-16 checksum helper interface.
 *
 * Provides standardized CRC-16 variants for both memory and file sources.
 *
 * Reflected variants use LSB-first processing.
 * Non-reflected variants use MSB-first processing.
 *
 * Variants supported:
 *   - crc16()          : CRC-16/IBM (ARC)
 *   - crc16_ibm()      : CRC-16/IBM
 *   - crc16_arc()      : CRC-16/ARC
 *   - crc16_modbus()   : CRC-16/MODBUS
 *   - crc16_usb()      : CRC-16/USB
 *   - crc16_ccitt()    : CRC-16/CCITT-FALSE
 *   - crc16_xmodem()   : CRC-16/XMODEM
 *   - crc16_kermit()   : CRC-16/KERMIT
 *   - crc16_dnp()      : CRC-16/DNP
 *
 * For each memory variant, a file-based counterpart exists, suffixed
 * with `_file`.
 *
 * Example:
 *     uint16_t a = crc16_modbus(data, len);
 *     uint16_t b = crc16_modbus_file("example.bin");
 */

#ifndef __CRC16_EXT_H__
#define __CRC16_EXT_H__

#include "crc16.h"

#ifdef __cplusplus
extern "C" {
#endif

extern uint16_t cccrc16(
	void (*crc16_table)(uint16_t *table, uint16_t poly),
	uint16_t (*ccrc16t)(
		uint16_t crc,
		const void *data,
		size_t len,
		const uint16_t *table
	),
	const void *data,
	size_t len,
	uint16_t poly,
	uint16_t init,
	uint16_t xorout
);

/* === Memory-based CRC16 variants === */

extern uint16_t crc16(const void *data, size_t len);
extern uint16_t crc16_ibm(const void *data, size_t len);
extern uint16_t crc16_arc(const void *data, size_t len);
extern uint16_t crc16_modbus(const void *data, size_t len);
extern uint16_t crc16_usb(const void *data, size_t len);
extern uint16_t crc16_ccitt(const void *data, size_t len);
extern uint16_t crc16_xmodem(const void *data, size_t len);
extern uint16_t crc16_kermit(const void *data, size_t len);
extern uint16_t crc16_dnp(const void *data, size_t len);

#ifdef LIBHASH_USE_FILE

/* === File-based CRC16 variants === */

extern uint16_t crc16_file(const char *path);
extern uint16_t crc16_ibm_file(const char *path);
extern uint16_t crc16_arc_file(const char *path);
extern uint16_t crc16_modbus_file(const char *path);
extern uint16_t crc16_usb_file(const char *path);
extern uint16_t crc16_ccitt_file(const char *path);
extern uint16_t crc16_xmodem_file(const char *path);
extern uint16_t crc16_kermit_file(const char *path);
extern uint16_t crc16_dnp_file(const char *path);

#ifdef LIBHASH_USE_FD
extern uint16_t crc16_fd(int fd);
extern uint16_t crc16_ibm_fd(int fd);
extern uint16_t crc16_arc_fd(int fd);
extern uint16_t crc16_modbus_fd(int fd);
extern uint16_t crc16_usb_fd(int fd);
extern uint16_t crc16_ccitt_fd(int fd);
extern uint16_t crc16_xmodem_fd(int fd);
extern uint16_t crc16_kermit_fd(int fd);
extern uint16_t crc16_dnp_fd(int fd);
#else
#include <stdio.h>
extern uint16_t crc16_fp(FILE *fp);
extern uint16_t crc16_ibm_fp(FILE *fp);
extern uint16_t crc16_arc_fp(FILE *fp);
extern uint16_t crc16_modbus_fp(FILE *fp);
extern uint16_t crc16_usb_fp(FILE *fp);
extern uint16_t crc16_ccitt_fp(FILE *fp);
extern uint16_t crc16_xmodem_fp(FILE *fp);
extern uint16_t crc16_kermit_fp(FILE *fp);
extern uint16_t crc16_dnp_fp(FILE *fp);
#endif /* LIBHASH_USE_FD */
#endif /* LIBHASH_USE_FILE */

#ifdef __cplusplus
}
#endif

#endif /* __CRC16_EXT_H__ */
