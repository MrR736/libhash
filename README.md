# **libhash / WjCryptLib Header-Only Fork**

**Version:** 1.0.1

**libhash** is a lightweight, header-only fork of the popular **WjCryptLib** C cryptography library.
Each header in the `src/` directory embeds both the original `.h` and `.c` implementation, allowing you to integrate cryptographic algorithms with:

* **Zero linking**
* **Zero build steps**
* **Zero external dependencies**

This makes it ideal for **embedded systems**, **sandboxed environments**, and **single-translation-unit** C/C++ projects.

---

## **Key Features**

* **True header-only design**
  Every algorithm is fully self-contained in a single header. No `.c` files, library builds, or additional sources are required.

* **Modular usage**
  Include only the algorithms you need. No global umbrella header, no unnecessary code.

* **C and C++ compatible**
  Minimal dependencies, fully portable, and works in both C and C++ projects.

* **Great for constrained environments**
  Perfect for embedded platforms, static builds, plugin systems, or sandboxed applications.

* **Minimal dependencies**
  Only standard C headers are required.

---

## **Available Algorithms**

```
src/
├── cipher
│   ├── affine.h        // Affine Cipher
│   ├── atbash.h        // Atbash Cipher
│   ├── caesar.h        // Caesar Cipher
│   ├── customcipher.h  // Custom Cipher
│   ├── playfair.h      // Playfair Cipher
│   └── vigenere.h      // Vigenere Cipher
├── aes.h               // AES base
├── aescbc.h            // AES in CBC mode
├── aesctr.h            // AES in CTR mode
├── aesofb.h            // AES in OFB mode
├── base8.h             // Base8 encoder/decoder
├── base16.h            // Base16 encoder/decoder
├── base32.h            // Base32 encoder/decoder
├── base58.h            // Base58 encoder/decoder
├── base64.h            // Base64 encoder/decoder
├── crc8.h              // CRC8
├── crc8_ext.h          // CRC8 (external variant)
├── crc16.h             // CRC16
├── crc16_ext.h         // CRC16 (external variant)
├── crc32.h             // CRC32
├── crc32_ext.h         // CRC32 (external variant)
├── crc64.h             // CRC64
├── crc64_ext.h         // CRC64 (external variant)
├── md2.h               // MD2 hash
├── md4.h               // MD4 hash
├── md5.h               // MD5 hash
├── rc4.h               // RC4 Stream Cipher
├── sha0.h              // SHA-0 hash
├── sha1.h              // SHA-1 hash
├── sha224.h            // SHA-224 hash
├── sha256.h            // SHA-256 hash
├── sha3-256.h          // SHA3-256 hash
├── sha3-512.h          // SHA3-512 hash
├── sha384.h            // SHA384 hash
├── sha512-224.h        // SHA512/224 hash
├── sha512-256.h        // SHA512/256 hash
└── sha512.h            // SHA512 hash
```

Each header wraps the corresponding WjCryptLib `.h` and `.c` source into a single self-contained file.

---

## **Usage**

Simply include the header for the algorithm you need:

```c
#include "sha256.h"

SHA256_HASH hash;
Sha256Calculate("hello", 5, &hash);
```

No build scripts, no library linking, no extra configuration.

---

## **Memory & Platform Abstraction**

`libhash` provides **portable replacements** for standard memory and string functions to ensure safe operation across different platforms:

* `libhash_memset`  / `libhash_memcpy`  / `libhash_realloc` / `libhash_calloc`
* `libhash_strlen`  / `libhash_tolower` / `libhash_toupper` / `libhash_isalpha`
* `libhash_isspace`

These are automatically mapped to the standard functions when appropriate.

---

## **CMake Build & Tests**

A lightweight CMake setup supports building the library, including an embedded configuration:

```bash
cmake -S . -B build -DLIBHASH_EMBEDDED=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
cd build
ctest
```

For a standard build without the embedded configuration:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
cd build
ctest
```

Tests for the supported algorithms are available in the `test/` directory.

---

## **License**

This project is licensed under **GPL-3.0**. See the `LICENSE` file for full terms.

---

## **Acknowledgments**

* Original cryptographic code: **WaterJuice/WjCryptLib**
  Source: [WjCryptLib](https://github.com/WaterJuice/WjCryptLib)

* Header-only fork and restructuring: **MrR736**
  <[MrR736@users.github.com](mailto:MrR736@users.github.com)>
