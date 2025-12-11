# **libhash / WjCryptLib Header-Only Fork**

**Version:** 1.0.0

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
├── aes.h         // AES base
├── aescbc.h      // AES in CBC mode
├── aesctr.h      // AES in CTR mode
├── aesofb.h      // AES in OFB mode
├── base16.h      // Base16 encoder/decoder
├── base32.h      // Base32 encoder/decoder
├── base64.h      // Base64 encoder/decoder
├── crc32.h       // CRC32
├── crc32_ext.h   // CRC32 (external variant)
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

* `libhash_memset` / `libhash_memcpy`
* `libhash_strlen` / `libhash_tolower` / `libhash_toupper`

These are automatically mapped to the standard functions when appropriate.

---

## **CMake Build & Tests**

A lightweight CMake setup allows building tests or the shared library:

```bash
mkdir build && cd build
cmake ..
cmake --build .
ctest
```

Tests are available for all algorithms in the `test/` directory.

---

## **License**

This project is licensed under **GPL-3.0**. See the `LICENSE` file for full terms.

---

## **Acknowledgments**

* Original cryptographic code: **Wishray/WjCryptLib**
  Source: [https://github.com/WaterJuice/WjCryptLib](https://github.com/WaterJuice/WjCryptLib)

* Header-only fork and restructuring: **MrR736**
  <[MrR736@users.github.com](mailto:MrR736@users.github.com)>
