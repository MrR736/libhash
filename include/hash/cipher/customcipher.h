/**
 * WjCryptLib_customcipher
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

#ifndef __CUSTOMCIPHER_H__
#define __CUSTOMCIPHER_H__

#include <stdint.h>
#include <stddef.h>

#ifndef CALLBACK
#define CALLBACK
#endif

#define CUSTOMCIPHER_SUCCESS          0
#define CUSTOMCIPHER_ERR_INVALID_ARG -1
#define CUSTOMCIPHER_ERR_ALLOC_FAIL  -2
#define CUSTOMCIPHER_ERR_BAD_KEY     -3
#define CUSTOMCIPHER_ERR_BAD_DATA    -4

#ifdef __cplusplus
extern "C" {
#endif

typedef int (CALLBACK *cipher_encrypt)(const void *data,size_t len,void **out,size_t *out_len);
typedef int (CALLBACK *cipher_decrypt)(const void *data,size_t len,void **out,size_t *out_len);

/*
 * Custom cipher object.
 */
typedef struct customcipher {
	cipher_encrypt encrypt;
	cipher_decrypt decrypt;
} customcipher;

// Initialize custom cipher.
extern int customcipher_init(customcipher *cipher,cipher_encrypt encrypt,cipher_decrypt decrypt);

// Encrypt data.
extern int customcipher_encrypt(const customcipher *cipher,const void *data,size_t len,void **out,size_t *out_len);

// Decrypt data.
extern int customcipher_decrypt(const customcipher *cipher,const void *data,size_t len,void **out,size_t *out_len);

// Encrypt data String.
extern int customcipher_encrypt_string(const customcipher *cipher,const char *data,size_t len,char **out,size_t *out_len);

// Decrypt data String.
extern int customcipher_decrypt_string(const customcipher *cipher,const char *data,size_t len,char **out,size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* __CUSTOMCIPHER_H__ */
