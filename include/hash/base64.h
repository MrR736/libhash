/**
 * WjCryptLib_base64
 *
 * Copyright (C) 2025 MrR736 <MrR736@users.github.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __BASE64_H__
#define __BASE64_H__

#include <stddef.h>
#include <stdint.h>

#define BASE64_SUCCESS		 0
#define BASE64_ERR_INVALID_ARG	-1
#define BASE64_ERR_ALLOC_FAIL	-2
#define BASE64_ERR_BAD_CHAR	-3

typedef struct {
	const char *alphabet;	// 64-character alphabet
	char pad;		// padding character ('=' or 0 for none)
	int case_insensitive;	// 1 to decode in case-insensitive mode
} base64_config_t;

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- Encode ---------- */
extern char *base64_encode_custom(const void *data, size_t len, const base64_config_t *cfg);

/* ---------- Decode ---------- */
extern int base64_decode_custom(const char *str, const base64_config_t *cfg, void **out, size_t *out_len);

/* ---------- Convenience Wrappers ---------- */
extern char *base64_encode(const void *data, size_t len);
extern int base64_decode(const char *str, void **out, size_t *out_len);

/* ---------- URL-safe variant ---------- */
extern char *base64url_encode(const void *data, size_t len);
extern int base64url_decode(const char *str, void **out, size_t *out_len);

/* ---------- MIME (RFC 2045) variant ---------- */
extern char *base64mime_encode(const void *data, size_t len);
extern int base64mime_decode(const char *str, void **out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* __BASE64_H__ */
