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

#if defined(_MSC_VER) && _MSC_VER < 1900 && !defined(inline)
#define inline __inline
#endif

#ifndef LIBHASH_VISIBILITY
#if (defined(__GNUC__) &&  (__GNUC__ >= 4) && (__GNUC_MINOR__ > 2)) || __has_attribute(visibility)
#define LIBHASH_VISIBILITY(V) __attribute__ ((visibility (#V)))
#else
#define LIBHASH_VISIBILITY(V)
#endif
#endif

#ifndef LIBHASH_EXPORT
#ifdef _WIN32
#define LIBHASH_EXPORT __declspec(dllexport)
#else
#define LIBHASH_EXPORT LIBHASH_VISIBILITY(default)
#endif
#endif

#ifndef LIBHASH_IMPORT
#ifdef _WIN32
#define LIBHASH_IMPORT __declspec(dllimport)
#else
#define LIBHASH_IMPORT LIBHASH_VISIBILITY(default)
#endif
#endif

#ifndef LIBHASH_INLINE_API
#define LIBHASH_INLINE_API static inline
#endif

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
LIBHASH_INLINE_API int customcipher_init(customcipher *cipher,cipher_encrypt encrypt,cipher_decrypt decrypt) {
	if (!cipher || !encrypt || !decrypt) return CUSTOMCIPHER_ERR_INVALID_ARG;
	cipher->encrypt = encrypt;
	cipher->decrypt = decrypt;
	return CUSTOMCIPHER_SUCCESS;
}

// Encrypt data.
LIBHASH_INLINE_API int customcipher_encrypt(const customcipher *cipher,const void *data,size_t len,void **out,size_t *out_len) {
	if (!cipher || !cipher->encrypt || !out || !out_len) return CUSTOMCIPHER_ERR_INVALID_ARG;
	if (!data && len != 0) return CUSTOMCIPHER_ERR_INVALID_ARG;
	*out = NULL;
	*out_len = 0;
	return cipher->encrypt(data,len,out,out_len);
}

// Decrypt data.
LIBHASH_INLINE_API int customcipher_decrypt(const customcipher *cipher,const void *data,size_t len,void **out,size_t *out_len) {
	if (!cipher || !cipher->decrypt || !out || !out_len) return CUSTOMCIPHER_ERR_INVALID_ARG;
	if (!data && len != 0) return CUSTOMCIPHER_ERR_INVALID_ARG;
	*out = NULL;
	*out_len = 0;
	return cipher->decrypt(data,len,out,out_len);
}

// Encrypt data String.
LIBHASH_INLINE_API int customcipher_encrypt_string(const customcipher *cipher,const char *data,size_t len,char **out,size_t *out_len) {
	return customcipher_encrypt(cipher,(const void*)data,len,(void**)out,out_len);
}

// Decrypt data String.
LIBHASH_INLINE_API int customcipher_decrypt_string(const customcipher *cipher,const char *data,size_t len,char **out,size_t *out_len) {
	return customcipher_decrypt(cipher,(const void*)data,len,(void**)out,out_len);
}

#ifdef __cplusplus
}
#endif

#endif /* __CUSTOMCIPHER_H__ */
