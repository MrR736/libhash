/* SPDX-License-Identifier: GPL-3.0 */
#ifndef __CRC16_EXT_H__
#define __CRC16_EXT_H__

#include "crc16.h"

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
 * CRC-16 Extended Helper Layer
 *
 * Defines memory and file-based variants for common CRC-16 families.
 *
 * Reflected variants use LSB-first processing.
 * Non-reflected variants use MSB-first processing.
 */

#ifdef __cplusplus
extern "C" {
#endif


LIBHASH_INLINE_API uint16_t cccrc16(
	void (*crc16_table)(
		uint16_t *table,
		uint16_t poly
	),
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
) {
	if (!crc16_table || !ccrc16t || !data || len == 0)
		return 0;

	uint16_t table[256];

	crc16_table(table, poly);

	return (uint16_t)(
		ccrc16t(init, data, len, table) ^ xorout
	);
}


/* === Compute CRC-16 over memory === */

#undef __CRC16_FUNCTION__

#define __CRC16_FUNCTION__(tablec, ccrcc, name, poly, init, xorout) \
LIBHASH_INLINE_API uint16_t name(const void *data,size_t len) { \
	if (!data || len == 0) return 0; \
	uint16_t table[256]; \
	tablec(table, (poly)); \
	return (uint16_t)(ccrcc((init), data, len, table) ^ (xorout)); \
}


/* === CRC-16/IBM === */
__CRC16_FUNCTION__(crc16_reflected_table,ccrc16_reflected,crc16,CRC16_IBM_POLY_REFLECTED,0x0000U,0x0000U)
__CRC16_FUNCTION__(crc16_reflected_table,ccrc16_reflected,crc16_ibm,CRC16_IBM_POLY_REFLECTED,0x0000U,0x0000U)
__CRC16_FUNCTION__(crc16_reflected_table,ccrc16_reflected,crc16_arc,CRC16_IBM_POLY_REFLECTED,0x0000U,0x0000U)

/* === CRC-16/MODBUS === */
__CRC16_FUNCTION__(crc16_reflected_table,ccrc16_reflected,crc16_modbus,CRC16_MODBUS_POLY_REFLECTED,0xFFFFU,0x0000U)

/* === CRC-16/USB === */
__CRC16_FUNCTION__(crc16_reflected_table,ccrc16_reflected,crc16_usb,CRC16_USB_POLY_REFLECTED,0xFFFFU,0xFFFFU)

/* === CRC-16/CCITT-FALSE === */
__CRC16_FUNCTION__(crc16_init_table,ccrc16,crc16_ccitt,CRC16_CCITT_POLY,0xFFFFU,0x0000U)

/* === CRC-16/XMODEM === */
__CRC16_FUNCTION__(crc16_init_table,ccrc16,crc16_xmodem,CRC16_XMODEM_POLY,0x0000U,0x0000U)

/* === CRC-16/KERMIT === */
__CRC16_FUNCTION__(crc16_reflected_table,ccrc16_reflected,crc16_kermit,CRC16_KERMIT_POLY_REFLECTED,0x0000U,0x0000U)

/* === CRC-16/DNP === */
__CRC16_FUNCTION__(crc16_reflected_table,ccrc16_reflected,crc16_dnp,CRC16_DNP_POLY_REFLECTED,0x0000U,0xFFFFU)

#undef __CRC16_FUNCTION__


#ifdef LIBHASH_USE_FILE

/* === Compute CRC-16 over file === */

#undef __CRC16_FILE_FUNCTION__

#ifdef LIBHASH_USE_FD

#define __CRC16_FILE_FUNCTION__(ctable, ccrcc, name, poly, init, xorout) \
LIBHASH_INLINE_API uint16_t name##_fd(int fd) { \
	if (fd < 0) return 0; \
	uint16_t table[256]; \
	ctable(table, (poly)); \
	uint16_t crc = (init); \
	uint8_t buf[4096]; \
	ssize_t n; \
	while ((n = read(fd, buf, sizeof(buf))) > 0) \
		crc = ccrcc(crc, buf, (size_t)n, table); \
	if (n < 0) return 0; \
	return (uint16_t)(crc ^ (xorout)); \
} \
LIBHASH_INLINE_API uint16_t name##_file(const char *path) { \
	if (!path) return 0; \
	int fd = open(path, O_RDONLY | O_BINARY); \
	if (fd < 0) return 0; \
	uint16_t crc = name##_fd(fd); \
	close(fd); \
	return crc; \
}

#else

#define __CRC16_FILE_FUNCTION__(ctable, ccrcc, name, poly, init, xorout) \
LIBHASH_INLINE_API uint16_t name##_fp(FILE *fp) { \
	if (!fp) return 0; \
	uint16_t table[256]; \
	ctable(table, (poly)); \
	uint16_t crc = (init); \
	uint8_t buf[4096]; \
	size_t n; \
	while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) \
		crc = ccrcc(crc, buf, n, table); \
	if (ferror(fp)) return 0; \
	return (uint16_t)(crc ^ (xorout)); \
} \
LIBHASH_INLINE_API uint16_t name##_file(const char *path) { \
	if (!path) return 0; \
	FILE *fp = fopen(path, "rb"); \
	if (!fp) return 0; \
	uint16_t crc = name##_fp(fp); \
	fclose(fp); \
	return crc; \
}

#endif /* LIBHASH_USE_FD */


/* === Reflected CRC-16 variants === */
__CRC16_FILE_FUNCTION__(crc16_reflected_table,ccrc16_reflected,crc16,CRC16_IBM_POLY_REFLECTED,0x0000U,0x0000U)
__CRC16_FILE_FUNCTION__(crc16_reflected_table,ccrc16_reflected,crc16_ibm,CRC16_IBM_POLY_REFLECTED,0x0000U,0x0000U)
__CRC16_FILE_FUNCTION__(crc16_reflected_table,ccrc16_reflected,crc16_arc,CRC16_IBM_POLY_REFLECTED,0x0000U,0x0000U)
__CRC16_FILE_FUNCTION__(crc16_reflected_table,ccrc16_reflected,crc16_modbus,CRC16_MODBUS_POLY_REFLECTED,0xFFFFU,0x0000U)
__CRC16_FILE_FUNCTION__(crc16_reflected_table,ccrc16_reflected,crc16_usb,CRC16_USB_POLY_REFLECTED,0xFFFFU,0xFFFFU)
__CRC16_FILE_FUNCTION__(crc16_reflected_table,ccrc16_reflected,crc16_kermit,CRC16_KERMIT_POLY_REFLECTED,0x0000U,0x0000U)
__CRC16_FILE_FUNCTION__(crc16_reflected_table,ccrc16_reflected,crc16_dnp,CRC16_DNP_POLY_REFLECTED,0x0000U,0xFFFFU)

/* === Non-reflected CRC-16 variants === */
__CRC16_FILE_FUNCTION__(crc16_init_table,ccrc16,crc16_ccitt,CRC16_CCITT_POLY,0xFFFFU,0x0000U)
__CRC16_FILE_FUNCTION__(crc16_init_table,ccrc16,crc16_xmodem,CRC16_XMODEM_POLY,0x0000U,0x0000U)


#undef __CRC16_FILE_FUNCTION__

#endif /* LIBHASH_USE_FILE */


#ifdef __cplusplus
}
#endif

#endif /* __CRC16_EXT_H__ */
