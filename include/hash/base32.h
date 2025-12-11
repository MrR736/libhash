/**
 * WjCryptLib_base32
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

#ifndef __BASE32_H__
#define __BASE32_H__

#include <stddef.h>
#include <stdint.h>

#define BASE32_SUCCESS 0
#define BASE32_ERR_INVALID_ARG  -1
#define BASE32_ERR_ALLOC_FAIL   -2
#define BASE32_ERR_BAD_CHAR     -3

typedef struct {
    const char *alphabet;  // 32-character alphabet
    char pad;              // padding character ('=' or 0 for none)
    int case_insensitive;  // 1 to decode in case-insensitive mode
} base32_config_t;

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- Encode ---------- */
extern char *base32_encode_custom(const void *data, size_t len, const base32_config_t *cfg);

/* ---------- Decode ---------- */
extern int base32_decode_custom(const char *str, const base32_config_t *cfg, void **out, size_t *out_len);

extern char *base32_encode(const void *data, size_t len);
extern int base32_decode(const char *str, void **out, size_t *out_len);

// ---------- Encoder ----------
extern char *base32hex_encode(const void *data, size_t len);

// ---------- Decoder ----------
extern int base32hex_decode(const char *str, void **out, size_t *out_len);

// ---------- Encoder ----------
extern char *zbase32_encode(const void *data, size_t len);

// ---------- Decoder ----------
extern int zbase32_decode(const char *str, void **out, size_t *out_len);

/* ---------------- Encoder ---------------- */
extern char *crockford_base32_encode(const void *data, size_t len);

/* ---------------- Decoder ---------------- */
extern int crockford_base32_decode(const char *str, void **out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* __BASE32_H__ */
