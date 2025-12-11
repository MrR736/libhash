// hash.c - Single compilation unit for header-only hash library

#include <stddef.h>  // for size_t
#include <stdint.h>  // for uintptr_t and intptr_t

// -----------------------------------------------------------------------------
// Export macro
// -----------------------------------------------------------------------------
#define LIBHASH_INLINE_API LIBHASH_EXPORT
#include "platforms.h"

// -----------------------------------------------------------------------------
// Header-only includes (all algorithms)
// -----------------------------------------------------------------------------
#include "aes.h"
#include "aescbc.h"
#include "aesctr.h"
#include "aesofb.h"

#include "crc32.h"
#include "crc32_ext.h"

#include "base16.h"
#include "base32.h"
#include "base64.h"

#include "md2.h"
#include "md4.h"
#include "md5.h"

#include "rc4.h"

#include "sha1.h"
#include "sha224.h"
#include "sha256.h"
#include "sha384.h"
#include "sha512.h"
