/*
 * WjCryptLib_Md5
 *
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <http://unlicense.org/>
 */

#ifndef __MD5I_H__
#define __MD5I_H__

#include <stdint.h>

#define MD5_HASH_SIZE 16

#ifdef __cplusplus
extern "C" {
#endif

// Md5Context - This must be initialised using Md5Initialised. Do not modify the contents of this structure directly.
typedef struct {
	uint32_t lo;
	uint32_t hi;
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
	uint8_t  buffer[64];
	uint32_t block[16];
} Md5Context;

typedef struct {
	uint8_t bytes[MD5_HASH_SIZE];
} MD5_HASH;

/*
 *  Md5Initialise
 *
 *  Initialises an MD5 Context. Use this to initialise/reset a context.
 */
extern void Md5Initialise(Md5Context*);

/*
 *  Md5Update
 *
 *  Adds data to the MD5 context. This will process the data and update the
 * internal state of the context. Keep on calling this function until all the
 * data has been added. Then call Md5Finalise to calculate the hash.
 */
extern void Md5Update(Md5Context*,const void*,uint32_t);

/*
 *  Md5Finalise
 *
 *  Performs the final calculation of the hash and returns the digest (16 byte
 * buffer containing 128bit hash). After calling this, Md5Initialised must be
 * used to reuse the context.
 */
extern void Md5Finalise(Md5Context*, MD5_HASH*);

/*
 *  Md5Calculate
 *
 *  Combines Md5Initialise, Md5Update, and Md5Finalise into one function.
 * Calculates the MD5 hash of the buffer.
 */
extern void Md5Calculate(const void*,uint32_t,MD5_HASH *);

#ifdef __cplusplus
}
#endif

#endif // __MD5I_H__
