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
extern void playfair_remove_padding(char *text,size_t *len);

/*
 * Normalize character
 *
 * Lowercase is converted to uppercase.
 * J is converted to I.
 */
extern char playfair_normalize_char(char c);

/*
 * Build 5x5 Playfair matrix
 *
 * Duplicate letters in the key are removed.
 * J is omitted.
 */
extern int playfair_build_matrix(const char *key, char matrix[25]);

// Find character in matrix
extern int playfair_find_char(const char matrix[25], char c,size_t *row, size_t *col);

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
extern char *playfair_prepare_text(const char *text,size_t *out_len);

// Encrypt a pair
extern int playfair_encrypt_pair(const char matrix[25], char a,char b, char *out_a, char *out_b);

// Decrypt a pair
extern int playfair_decrypt_pair(const char matrix[25], char a,char b, char *out_a, char *out_b);

/*
 * Encrypt
 *
 * Returns an allocated uppercase ciphertext.
 * Non-alphabetic characters are removed.
 * J becomes I.
 *
 * Caller must free() the result.
 */
extern char *playfair_encrypt(const char *text,const char *key);

/*
 * Decrypt
 *
 * Returns an allocated uppercase plaintext.
 *
 * Note:
 * Playfair padding X cannot always be removed automatically,
 * because X may be a legitimate plaintext character.
 */
extern char *playfair_decrypt(const char *text,const char *key);

/*
 * In-place encryption
 *
 * The supplied buffer must already be prepared:
 *
 *   even length
 *   alphabetic characters only
 *   J converted to I
 */
extern int playfair_encrypt_inplace(char *text, size_t len,const char *key);

// In-place decryption
extern int playfair_decrypt_inplace(char *text, size_t len,const char *key);

/*
 * Build matrix as printable string
 *
 * Caller supplies at least 26 bytes.
 */
extern int playfair_matrix_string(const char *key, char *out);

#ifdef __cplusplus
}
#endif

#endif /* __PLAYFAIR_H__ */
