# **WjCryptLib Header-Only (Fork of WjCryptLib)**

A lightweight, header-only fork of the excellent **WjCryptLib** C cryptography library.
Each header in the `src/` directory embeds the original `.h` **and** `.c` implementation, allowing you to drop in individual cryptographic algorithms with *zero* linking, *zero* build steps, and *zero* external dependencies.

This design is ideal for **embedded systems**, **sandboxed environments**, and **single-translation-unit** C/C++ projects where simplicity and portability matter.

---

## **Key Features**

* **True header-only design**
  Every algorithm is fully self-contained in a single header—no `.c` files, library builds, or extra sources required.

* **Modular include-only usage**
  Include only the algorithms you need. No global umbrella header, no unnecessary code.

* **C and C++ compatible**
  Clean, dependency-minimal implementation that compiles in both C and C++ environments.

* **Great for constrained builds**
  Perfect for embedded platforms, static builds, plugin systems, or any environment where compiling extra source files is undesirable.

* **Minimal dependencies**
  Uses only standard C headers.

---

## **Available Algorithms**

```
src/
├── aes.h         // AES base
├── aescbc.h      // AES in CBC mode
├── aesctr.h      // AES in CTR mode
├── aesofb.h      // AES in OFB mode
├── base16.h      // Base16 encoder/decoder
├── base32.h      // Base32 encoder/decoder
├── base64.h      // Base64 encoder/decoder
├── crc32.h       // CRC32
├── crc32_ext.h   // CRC32 (extern variant)
├── md2.h         // MD2 hash
├── md4.h         // MD4 hash
├── md5.h         // MD5 hash
├── rc4.h         // RC4 stream cipher
├── sha1.h        // SHA-1 hash
├── sha224.h      // SHA-224 hash
├── sha256.h      // SHA-256 hash
├── sha384.h      // SHA-384 hash
└── sha512.h      // SHA-512 hash
```

Each file wraps its corresponding WjCryptLib `.h` and `.c` into a single unit.

---

## **Usage**

Just include the algorithm you need:

```c
#include "sha256.h"

SHA256_HASH hash;
Sha256Calculate("hello", 5, &hash);
```

No build scripts, no library linking, no extra configuration.

---

## **License**

This project is licensed under **GPL-3.0**.
See `LICENSE` for full terms.

---

## **Acknowledgments**

Original cryptographic implementations by **Wishray/WjCryptLib**
Source: [https://github.com/WaterJuice/WjCryptLib](https://github.com/WaterJuice/WjCryptLib)

Header-only conversion and restructuring by **MrR736**
<[MrR736@users.github.com](mailto:MrR736@users.github.com)>
