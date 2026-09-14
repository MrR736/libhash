#ifndef HASH_H
#define HASH_H

#include "crc8.h"
#include "crc8_ext.h"
#include "crc16.h"
#include "crc16_ext.h"
#include "crc32.h"
#include "crc32_ext.h"
#include "crc64.h"
#include "crc64_ext.h"

#include "md2.h"
#include "md4.h"
#include "md5.h"

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

#include "base16.h"
#include "base32.h"
#include "base58.h"
#include "base64.h"

#include "aes.h"
#include "aescbc.h"
#include "aesctr.h"
#include "aesofb.h"

#include "rc4.h"

#define HashCalculate(FuncCalculate,TYPE_HASH,Buffer,BufferSize,Digest) \
({ \
	TYPE_HASH hash; \
	FuncCalculate(Buffer,(uint32_t)BufferSize, &hash); \
	Digest = hash.bytes; \
})

#endif
