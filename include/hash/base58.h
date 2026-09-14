/**
 * WjCryptLib_base58
 *
 * Copyright (C) 2026 MrR736 <MrR736@users.github.com>
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
 */

#ifndef __BASE58_H__
#define __BASE58_H__

#include <stdint.h>
#include <stddef.h>

#define BASE58_SUCCESS			0
#define BASE58_ERR_INVALID_ARG	-1
#define BASE58_ERR_ALLOC_FAIL	-2
#define BASE58_ERR_BAD_CHAR		-3

typedef struct {
	const char *alphabet;
	int case_insensitive;
} base58_config_t;

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- Encode ---------- */
extern char *base58_encode_custom(const void *data,size_t len,const base58_config_t *cfg);

/* ---------- Decode ---------- */
extern int base58_decode_custom(const char *str,const base58_config_t *cfg,void **out,size_t *out_len);


/* ---------- Bitcoin Base58 ---------- */
extern char *base58_encode(const void *data,size_t len);
extern int base58_decode(const char *str,void **out,size_t *out_len);

/* ---------- Base58Check-compatible alphabet ---------- */
extern char *base58btc_encode(const void *data,size_t len);
extern int base58btc_decode(const char *str,void **out,size_t *out_len);

/* ---------- Ripple (XRPL) Base58 ---------- */
extern char *base58ripple_encode(const void *data,size_t len);
extern int base58ripple_decode(const char *str,void **out,size_t *out_len);

/* ---------- Flickr Base58 ---------- */
extern char *base58flickr_encode(const void *data,size_t len);
extern int base58flickr_decode(const char *str,void **out,size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* __BASE58_H__ */
