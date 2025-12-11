/**
 * WjCryptLib_base16
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

#ifndef __BASE16_H__
#define __BASE16_H__

#include <stdint.h>
#include <stddef.h>

#define BASE16_SUCCESS		 0
#define BASE16_ERR_INVALID_ARG	-1
#define BASE16_ERR_ALLOC_FAIL	-2
#define BASE16_ERR_BAD_CHAR	-3

typedef struct {
	const char *alphabet;
	int case_insensitive;
} base16_config_t;

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- Encode ---------- */
extern char *base16_encode_custom(const void *data, size_t len, const base16_config_t *cfg);


/* ---------- Decode ---------- */
extern int base16_decode_custom(const char *str, const base16_config_t *cfg,void **out, size_t *out_len);

extern char *base16_encode(const void *data, size_t len, int uppercase);
extern int base16_decode(const char *str, void **out, size_t *out_len, int uppercase);

#ifdef __cplusplus
}
#endif

#endif /* __BASE16_H__ */
