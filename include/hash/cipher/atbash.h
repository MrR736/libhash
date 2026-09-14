/**
 * WjCryptLib_atbash
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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __ATBASH_H__
#define __ATBASH_H__

#include <stdint.h>
#include <stddef.h>

#define ATBASH_SUCCESS			0
#define ATBASH_ERR_INVALID_ARG	-1
#define ATBASH_ERR_ALLOC_FAIL	-2

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Single character
 *
 * A -> Z
 * B -> Y
 * C -> X
 *
 * a -> z
 * b -> y
 * c -> x
 */
extern char atbash_char(char c);

/*
 * In-place transformation
 *
 * Atbash is symmetric:
 *
 * encrypt(encrypt(x)) == x
 *
 * Therefore the same function performs both encryption
 * and decryption.
 *
 */
extern int atbash_inplace(char *str, size_t len);

/*
 * String transformation
 *
 * Returns a newly allocated NUL-terminated string.
 * Caller must free() the returned buffer.
 */
extern char* atbash(const char *str);

/*
 * Buffer transformation
 *
 * Length is explicit, so arbitrary buffers can be processed.
 *
 * Note:
 * Atbash only transforms ASCII alphabetic bytes. All other
 * bytes are copied unchanged.
 */
extern int atbash_buffer(const void *data,size_t len,void **out);

/*
 * Explicit aliases
 *
 * Atbash encryption and decryption are identical operations.
 */
extern char* atbash_encrypt(const char *str);
extern char* atbash_decrypt(const char *str);

extern int atbash_encrypt_inplace(char *str, size_t len);
extern int atbash_decrypt_inplace(char *str, size_t len);

extern int atbash_encrypt_buffer(const void *data,size_t len,void **out);
extern int atbash_decrypt_buffer(const void *data,size_t len,void **out);

#ifdef __cplusplus
}
#endif

#endif /* __ATBASH_H__ */
