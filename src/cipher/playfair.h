/**
 * WjCryptLib_playfair
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

#ifndef __PLAYFAIR_H__
#define __PLAYFAIR_H__

#include <stdint.h>
#include <stddef.h>

#if !HASH_USE_CUSTOM_MEM
# include <ctype.h>
# include <stdlib.h>
# ifdef _WIN32
#  include <string.h>
# else
#  include <memory.h>
# endif
#endif

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

#define PLAYFAIR_SUCCESS			0
#define PLAYFAIR_ERR_INVALID_ARG	-1
#define PLAYFAIR_ERR_ALLOC_FAIL		-2
#define PLAYFAIR_ERR_BAD_KEY		-3
#define PLAYFAIR_ERR_BAD_TEXT		-4

#define PLAYFAIR_ALPHABET "ABCDEFGHIKLMNOPQRSTUVWXYZ"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Remove Playfair padding.
 *
 * A trailing X is considered padding when the decrypted
 * text has more than one character.
 */
LIBHASH_INLINE_API void playfair_remove_padding(char *text,size_t *len) {
	if (!text || !len || *len == 0) return;
	if (*len > 1 && text[*len - 1] == 'X') {
		text[*len - 1] = '\0';
		--(*len);
	}
}

/*
 * Normalize character
 *
 * Lowercase is converted to uppercase.
 * J is converted to I.
 */
LIBHASH_INLINE_API char playfair_normalize_char(char c) {
	if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
	if (c == 'J') c = 'I';
	return c;
}

/*
 * Build 5x5 Playfair matrix
 *
 * Duplicate letters in the key are removed.
 * J is omitted.
 */
LIBHASH_INLINE_API int playfair_build_matrix(const char *key, char matrix[25]) {
	if (!key || !matrix) return PLAYFAIR_ERR_INVALID_ARG;
	int used[26] = {0};
	size_t pos = 0;
	for (size_t i = 0; key[i] != '\0'; ++i) {
		char c = playfair_normalize_char(key[i]);
		if (!isalpha(c)) continue;
		if (c == 'J') c = 'I';
		const int index = c - 'A';
		if (!used[index]) {
			used[index] = 1;
			matrix[pos++] = c;
		}
	}

	for (size_t i = 0; i < 25; ++i) {
		char c = PLAYFAIR_ALPHABET[i];
		const int index = c - 'A';
		if (!used[index]) {
			used[index] = 1;
			matrix[pos++] = c;
		}
	}
	return pos == 25 ? PLAYFAIR_SUCCESS : PLAYFAIR_ERR_BAD_KEY;
}

// Find character in matrix
LIBHASH_INLINE_API int playfair_find_char(const char matrix[25], char c,size_t *row, size_t *col) {
	if (!matrix || !row || !col) return PLAYFAIR_ERR_INVALID_ARG;
	c = playfair_normalize_char(c);
	if (c == 'J') c = 'I';

	for (size_t i = 0; i < 25; ++i) {
		if (matrix[i] == c) {
			*row = i / 5;
			*col = i % 5;
			return PLAYFAIR_SUCCESS;
		}
	}
	return PLAYFAIR_ERR_BAD_TEXT;
}

/*
 * Prepare plaintext
 *
 * Rules:
 *
 *   HELLO
 *   HE LX LO
 *
 * Repeated letters in a pair receive X.
 * Odd length receives X.
 *
 * Non-alphabetic characters are ignored.
 */
LIBHASH_INLINE_API char *playfair_prepare_text(const char *text,size_t *out_len) {
	if (!text || !out_len) return NULL;
	size_t letters = 0;
	for (size_t i = 0; text[i] != '\0'; ++i) {
		if (isalpha(text[i])) ++letters;
	}

	/*
	 * Worst case:
	 *
	 * Every pair could contain repeated characters,
	 * requiring an extra X.
	 *
	 * Allocate enough space conservatively.
	 */
	if (letters > (SIZE_MAX - 2) / 2) return NULL;
	size_t capacity = letters * 2 + 2;
	char *out = (char *)malloc(capacity);
	if (!out) return NULL;
	size_t input_pos = 0;
	size_t output_pos = 0;
	char pending = '\0';
	while (text[input_pos] != '\0') {
		char c = text[input_pos++];
		if (!isalpha(c)) continue;
		c = playfair_normalize_char(c);
		if (pending == '\0') {
			pending = c;
			continue;
		}
		if (pending == c) {
			// Same letters cannot occupy the same pair.
			out[output_pos++] = pending;
			out[output_pos++] = 'X';
			pending = c;
		} else {
			out[output_pos++] = pending;
			out[output_pos++] = c;
			pending = '\0';
		}
	}
	if (pending != '\0') {
		out[output_pos++] = pending;
		out[output_pos++] = 'X';
	}
	out[output_pos] = '\0';
	*out_len = output_pos;
	return out;
}

// Encrypt a pair
LIBHASH_INLINE_API int playfair_encrypt_pair(const char matrix[25], char a,char b, char *out_a, char *out_b) {
	size_t row_a, col_a;
	size_t row_b, col_b;
	if (!matrix || !out_a || !out_b) return PLAYFAIR_ERR_INVALID_ARG;
	if (playfair_find_char(matrix, a, &row_a, &col_a) != PLAYFAIR_SUCCESS) return PLAYFAIR_ERR_BAD_TEXT;
	if (playfair_find_char(matrix, b, &row_b, &col_b) != PLAYFAIR_SUCCESS) return PLAYFAIR_ERR_BAD_TEXT;
	if (row_a == row_b) {
		// Same row: move right.
		*out_a = matrix[row_a * 5 + ((col_a + 1) % 5)];
		*out_b = matrix[row_b * 5 + ((col_b + 1) % 5)];
	} else if (col_a == col_b) {
		// Same column: move down.
		*out_a = matrix[((row_a + 1) % 5) * 5 + col_a];
		*out_b = matrix[((row_b + 1) % 5) * 5 + col_b];
	} else {
		// Rectangle: exchange columns.
		*out_a = matrix[row_a * 5 + col_b];
		*out_b = matrix[row_b * 5 + col_a];
	}
	return PLAYFAIR_SUCCESS;
}

// Decrypt a pair
LIBHASH_INLINE_API int playfair_decrypt_pair(const char matrix[25], char a,char b, char *out_a, char *out_b) {
	size_t row_a, col_a;
	size_t row_b, col_b;
	if (!matrix || !out_a || !out_b) return PLAYFAIR_ERR_INVALID_ARG;
	if (playfair_find_char(matrix, a, &row_a, &col_a) != PLAYFAIR_SUCCESS) return PLAYFAIR_ERR_BAD_TEXT;
	if (playfair_find_char(matrix, b, &row_b, &col_b) != PLAYFAIR_SUCCESS) return PLAYFAIR_ERR_BAD_TEXT;
	if (row_a == row_b) {
		// Same row: move left.
		*out_a = matrix[row_a * 5 + ((col_a + 4) % 5)];
		*out_b = matrix[row_b * 5 + ((col_b + 4) % 5)];
	} else if (col_a == col_b) {
		// Same column: move up.
		*out_a = matrix[((row_a + 4) % 5) * 5 + col_a];
		*out_b = matrix[((row_b + 4) % 5) * 5 + col_b];
	} else {
		// Rectangle: exchange columns.
		*out_a = matrix[row_a * 5 + col_b];
		*out_b = matrix[row_b * 5 + col_a];
	}
	return PLAYFAIR_SUCCESS;
}

/*
 * Encrypt
 *
 * Returns an allocated uppercase ciphertext.
 * Non-alphabetic characters are removed.
 * J becomes I.
 *
 * Caller must free() the result.
 */
LIBHASH_INLINE_API char *playfair_encrypt(const char *text,const char *key) {
	if (!text || !key) return NULL;
	char matrix[25];
	if (playfair_build_matrix(key, matrix) != PLAYFAIR_SUCCESS) return NULL;
	size_t prepared_len = 0;
	char *prepared = playfair_prepare_text(text, &prepared_len);
	if (!prepared) return NULL;
	char *out = (char *)malloc(prepared_len + 1);
	if (!out) {
		free(prepared);
		return NULL;
	}
	for (size_t i = 0; i < prepared_len; i += 2) {
		if (playfair_encrypt_pair(matrix, prepared[i], prepared[i + 1], &out[i],&out[i + 1]) != PLAYFAIR_SUCCESS) {
			free(prepared);
			free(out);
			return NULL;
		}
	}
	out[prepared_len] = '\0';
	free(prepared);
	return out;
}

/*
 * Decrypt
 *
 * Returns an allocated uppercase plaintext.
 *
 * Note:
 * Playfair padding X cannot always be removed automatically,
 * because X may be a legitimate plaintext character.
 */
LIBHASH_INLINE_API char *playfair_decrypt(const char *text,const char *key) {
	if (!text || !key) return NULL;
	char matrix[25];
	if (playfair_build_matrix(key, matrix) != PLAYFAIR_SUCCESS) return NULL;
	size_t len = 0;
	for (size_t i = 0; text[i] != '\0'; ++i) {
		if (isalpha(text[i])) ++len;
	}
	if (len == 0) return (char *)calloc(1, 1);
	if (len & 1) return NULL;
	char *out = (char *)malloc(len + 1);
	if (!out) return NULL;
	size_t pos = 0;
	for (size_t i = 0; text[i] != '\0'; ++i) {
		if (!isalpha(text[i])) continue;
		out[pos++] = playfair_normalize_char(text[i]);
	}
	for (size_t i = 0; i < len; i += 2) {
		char a;
		char b;
		if (playfair_decrypt_pair(matrix, out[i], out[i + 1], &a, &b) != PLAYFAIR_SUCCESS) {
		free(out);
		return NULL;
		}
		out[i] = a;
		out[i + 1] = b;
	}
	out[len] = '\0';
	return out;
}

/*
 * In-place encryption
 *
 * The supplied buffer must already be prepared:
 *
 *   even length
 *   alphabetic characters only
 *   J converted to I
 */
LIBHASH_INLINE_API int playfair_encrypt_inplace(char *text, size_t len,const char *key) {
	if ((!text && len != 0) || !key) return PLAYFAIR_ERR_INVALID_ARG;
	if (len & 1) return PLAYFAIR_ERR_BAD_TEXT;
	char matrix[25];
	if (playfair_build_matrix(key, matrix) != PLAYFAIR_SUCCESS) return PLAYFAIR_ERR_BAD_KEY;
	for (size_t i = 0; i < len; i += 2) {
		char a;
		char b;
		if (playfair_encrypt_pair(matrix, text[i], text[i + 1], &a, &b) != PLAYFAIR_SUCCESS) return PLAYFAIR_ERR_BAD_TEXT;
		text[i] = a;
		text[i + 1] = b;
	}
	return PLAYFAIR_SUCCESS;
}

// In-place decryption
LIBHASH_INLINE_API int playfair_decrypt_inplace(char *text, size_t len,const char *key) {
	if ((!text && len != 0) || !key) return PLAYFAIR_ERR_INVALID_ARG;
	if (len & 1) return PLAYFAIR_ERR_BAD_TEXT;
	char matrix[25];
	if (playfair_build_matrix(key, matrix) != PLAYFAIR_SUCCESS) return PLAYFAIR_ERR_BAD_KEY;
	for (size_t i = 0; i < len; i += 2) {
		char a;
		char b;
		if (playfair_decrypt_pair(matrix, text[i], text[i + 1], &a, &b) != PLAYFAIR_SUCCESS) return PLAYFAIR_ERR_BAD_TEXT;
		text[i] = a;
		text[i + 1] = b;
	}
	return PLAYFAIR_SUCCESS;
}

/*
 * Build matrix as printable string
 *
 * Caller supplies at least 26 bytes.
 */
LIBHASH_INLINE_API int playfair_matrix_string(const char *key, char *out) {
	if (!key || !out) return PLAYFAIR_ERR_INVALID_ARG;
	char matrix[25];
	int result = playfair_build_matrix(key, matrix);
	if (result != PLAYFAIR_SUCCESS) return result;
	for (size_t i = 0; i < 25; ++i) out[i] = matrix[i];
	out[25] = '\0';
	return PLAYFAIR_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#endif /* __PLAYFAIR_H__ */
