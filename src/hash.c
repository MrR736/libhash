// hash.c - Single compilation unit for header-only hash library

#include <stddef.h>
#include <stdint.h>

// Export macro
#define LIBHASH_INLINE_API LIBHASH_EXPORT
#include "platforms.h"

// Header-only includes (all algorithms)
#include "aes.h"
#include "aescbc.h"
#include "aesctr.h"
#include "aesofb.h"

#include "crc8.h"
#include "crc8_ext.h"
#include "crc16.h"
#include "crc16_ext.h"
#include "crc32.h"
#include "crc32_ext.h"
#include "crc64.h"
#include "crc64_ext.h"

#include "base16.h"
#include "base32.h"
#include "base58.h"
#include "base64.h"

#include "md2.h"
#include "md4.h"
#include "md5.h"

#include "rc4.h"

#include "sha0.h"
#include "sha1.h"
#include "sha224.h"
#include "sha256.h"
#include "sha384.h"
#include "sha512.h"

#include "sha3-256.h"
#include "sha3-512.h"

#include "sha512-224.h"
#include "sha512-256.h"

#include "cipher/affine.h"
#include "cipher/atbash.h"
#include "cipher/caesar.h"
#include "cipher/customcipher.h"
#include "cipher/playfair.h"
#include "cipher/vigenere.h"
