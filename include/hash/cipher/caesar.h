/**
 * WjCryptLib_caesar
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

#ifndef __CAESAR_H__
#define __CAESAR_H__

#include <stdint.h>
#include <stddef.h>

#define CAESAR_SUCCESS		   0
#define CAESAR_ERR_INVALID_ARG -1
#define CAESAR_ERR_ALLOC_FAIL  -2

#ifdef __cplusplus
extern "C" {
#endif

extern int caesar_normalize_shift(int shift);

extern char caesar_shift_char(char c, int shift);

// Single character
extern char caesar_encrypt_char(char c, int shift);

extern char caesar_decrypt_char(char c, int shift);

// In-place encryption
extern int caesar_encrypt_inplace(char *str, size_t len, int shift);

// In-place decryption
extern int caesar_decrypt_inplace(char *str, size_t len, int shift);

/*
 * String encryption
 *
 * Returns a newly allocated NUL-terminated string.
 * Caller must free() the returned buffer.
 */
extern char* caesar_encrypt(const char *str, int shift);

/*
 * String decryption
 *
 * Returns a newly allocated NUL-terminated string.
 * Caller must free() the returned buffer.
 */
extern char *caesar_decrypt(const char *str, int shift);

/*
 * Buffer encryption
 *
 * Works with binary-safe buffers because length is explicit.
 */
extern int caesar_encrypt_buffer(const void *data,size_t len,int shift,void **out);

// Buffer decryption
extern int caesar_decrypt_buffer(const void *data,size_t len,int shift,void **out);

#ifdef __cplusplus
}
#endif

#endif /* __CAESAR_H__ */
