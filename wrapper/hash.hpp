/**
 * WjCryptLib for C++
 *
 * Copyright (C) 2025 MrR736 <MrR736@users.github.com>
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

#ifndef HASH_HPP
#define HASH_HPP

#include <array>
#include <cstddef>
#include <string>
#include <vector>
#include <stdexcept>
#include <cstdint>
#include <cstring>

#include "crc32.h"
#include "crc32_ext.h"

#include "md2.h"
#include "md4.h"
#include "md5.h"

#include "sha1.h"
#include "sha224.h"
#include "sha256.h"
#include "sha384.h"
#include "sha512.h"

#include "base16.h"
#include "base32.h"
#include "base64.h"

#include "aes.h"
#include "aescbc.h"
#include "aesctr.h"
#include "aesofb.h"

#include "rc4.h"

namespace hash {
	class Md2 {
		Md2Context ctx{};
		MD2_HASH hash{};

	public:
		Md2() {
			Md2Initialise(&ctx);
		}

		void update(const void* data, uint32_t len) {
			Md2Update(&ctx, data, len);
		}

		const MD2_HASH& finalize() {
			Md2Finalise(&ctx, &hash);
			return hash;
		}

		static MD2_HASH calculate(const void* data, size_t len) {
			MD2_HASH h{};
			Md2Calculate(data,len, &h);
			return h;
		}
		const MD2_HASH& get() const { return hash; }
	};

	class Md4 {
		Md4Context ctx{};
		MD4_HASH hash{};

	public:
		Md4() {
			Md4Initialise(&ctx);
		}

		void update(const void* data, uint32_t len) {
			Md4Update(&ctx, data, len);
		}

		const MD4_HASH& finalize() {
			Md4Finalise(&ctx, &hash);
			return hash;
		}

		static MD4_HASH calculate(const void* data, uint32_t len) {
			MD4_HASH h{};
			Md4Calculate(data, len, &h);
			return h;
		}
		const MD4_HASH& get() const { return hash; }
	};

	class Md5 {
		Md5Context ctx{};
		MD5_HASH hash{};

	public:
		Md5() {
			Md5Initialise(&ctx);
		}

		void update(const void* data, uint32_t len) {
			Md5Update(&ctx, data, len);
		}

		const MD5_HASH& finalize() {
			Md5Finalise(&ctx, &hash);
			return hash;
		}

		static MD5_HASH calculate(const void* data, uint32_t len) {
			MD5_HASH h{};
			Md5Calculate(data, len, &h);
			return h;
		}
		const MD5_HASH& get() const { return hash; }
	};

	class Sha1 {
		Sha1Context ctx{};
		SHA1_HASH hash{};

	public:
		Sha1() {
			Sha1Initialise(&ctx);
		}

		void update(const void* data, uint32_t len) {
			Sha1Update(&ctx, data, len);
		}

		const SHA1_HASH& finalize() {
			Sha1Finalise(&ctx, &hash);
			return hash;
		}

		static SHA1_HASH calculate(const void* data, uint32_t len) {
			SHA1_HASH h{};
			Sha1Calculate(data, len, &h);
			return h;
		}
		const SHA1_HASH& get() const { return hash; }
	};

	class Sha224 {
		Sha224Context ctx{};
		SHA224_HASH hash{};

	public:
		Sha224() {
			Sha224Initialise(&ctx);
		}

		void update(const void* data, uint32_t len) {
			Sha224Update(&ctx, data, len);
		}

		const SHA224_HASH& finalize() {
			Sha224Finalise(&ctx, &hash);
			return hash;
		}

		static SHA224_HASH calculate(const void* data, uint32_t len) {
			SHA224_HASH h{};
			Sha224Calculate(data, len, &h);
			return h;
		}
		const SHA224_HASH& get() const { return hash; }
	};

	class Sha256 {
		Sha256Context ctx{};
		SHA256_HASH hash{};

	public:
		Sha256() {
			Sha256Initialise(&ctx);
		}

		void update(const void* data, uint32_t len) {
			Sha256Update(&ctx, data, len);
		}

		const SHA256_HASH& finalize() {
			Sha256Finalise(&ctx, &hash);
			return hash;
		}

		static SHA256_HASH calculate(const void* data, uint32_t len) {
			SHA256_HASH h{};
			Sha256Calculate(data, len, &h);
			return h;
		}
		const SHA256_HASH& get() const { return hash; }
	};

	class Sha384 {
		Sha384Context ctx{};
		SHA384_HASH hash{};

	public:
		Sha384() {
			Sha384Initialise(&ctx);
		}

		void update(const void* data, uint32_t len) {
			Sha384Update(&ctx, data, len);
		}

		const SHA384_HASH& finalize() {
			Sha384Finalise(&ctx, &hash);
			return hash;
		}

		static SHA384_HASH calculate(const void* data, uint32_t len) {
			SHA384_HASH h{};
			Sha384Calculate(data, len, &h);
			return h;
		}
		const SHA384_HASH& get() const { return hash; }
	};

	class Sha512 {
		Sha512Context ctx{};
		SHA512_HASH hash{};

	public:
		Sha512() {
			Sha512Initialise(&ctx);
		}

		void update(const void* data, uint32_t len) {
			Sha512Update(&ctx, data, len);
		}

		const SHA512_HASH& finalize() {
			Sha512Finalise(&ctx, &hash);
			return hash;
		}

		static SHA512_HASH calculate(const void* data, uint32_t len) {
			SHA512_HASH h{};
			Sha512Calculate(data, len, &h);
			return h;
		}
		const SHA512_HASH& get() const { return hash; }
	};

	class Base16 {
	public:
		// Encode to std::string
		std::string encode(const void *data, size_t len, int uppercase) {
			char *cstr = base16_encode(data, len, uppercase);
			if (!cstr) throw std::runtime_error("base16_encode failed");
			std::string result(cstr);
			free(cstr);
			return result;
		}

		std::string encode_custom(const void *data, size_t len, const base16_config_t *cfg) {
			char *cstr = base16_encode_custom(data, len, cfg);
			if (!cstr) throw std::runtime_error("base16_encode_custom failed");
			std::string result(cstr);
			free(cstr);
			return result;
		}

		// Decode to vector<uint8_t>
		std::vector<uint8_t> decode(const std::string &str, int uppercase) {
			void *out = nullptr;
			size_t out_len = 0;
			if (base16_decode(str.c_str(), &out, &out_len, uppercase) != 0)
				throw std::runtime_error("base16_decode failed");
			std::vector<uint8_t> result((uint8_t*)out, (uint8_t*)out + out_len);
			free(out);
			return result;
		}

		std::vector<uint8_t> decode_custom(const std::string &str, const base16_config_t *cfg) {
			void *out = nullptr;
			size_t out_len = 0;
			if (base16_decode_custom(str.c_str(), cfg, &out, &out_len) != 0)
				throw std::runtime_error("base16_decode_custom failed");
			std::vector<uint8_t> result((uint8_t*)out, (uint8_t*)out + out_len);
			free(out);
			return result;
		}
	};

	class Base32 {
	public:
		// Standard encode/decode
		static std::string encode(const void* data, size_t len) {
			char* cstr = base32_encode(data, len);
			std::string result(cstr);
			free(cstr);
			return result;
		}

		static std::vector<uint8_t> decode(const std::string& str) {
			void* out = nullptr;
			size_t out_len = 0;
			int err = base32_decode(str.c_str(), &out, &out_len);
			if (err != BASE32_SUCCESS) throw std::runtime_error("Base32 decode failed");
			std::vector<uint8_t> result((uint8_t*)out, (uint8_t*)out + out_len);
			free(out);
			return result;
		}

		// Custom encode/decode
		static std::string encode_custom(const void* data, size_t len, const base32_config_t* cfg) {
			char* cstr = base32_encode_custom(data, len, cfg);
			std::string result(cstr);
			free(cstr);
			return result;
		}

		static std::vector<uint8_t> decode_custom(const std::string& str, const base32_config_t* cfg) {
			void* out = nullptr;
			size_t out_len = 0;
			int err = base32_decode_custom(str.c_str(), cfg, &out, &out_len);
			if (err != BASE32_SUCCESS) throw std::runtime_error("Base32 decode failed");
			std::vector<uint8_t> result((uint8_t*)out, (uint8_t*)out + out_len);
			free(out);
			return result;
		}

		static std::string encode_crockford(const void* data, size_t len) {
			char* cstr = crockford_base32_encode(data, len);
			std::string result(cstr);
			free(cstr);
			return result;
		}

		static std::vector<uint8_t> decode_crockford(const std::string &str) {
			void* out = nullptr;
			size_t out_len = 0;
			if (crockford_base32_decode(str.c_str(), &out, &out_len) != BASE32_SUCCESS)
				throw std::runtime_error("Crockford decode failed");
			std::vector<uint8_t> result((uint8_t*)out, (uint8_t*)out + out_len);
			free(out);
			return result;
		}

		static std::string encode_zbase32(const void* data, size_t len) {
			char* cstr = zbase32_encode(data, len);
			std::string result(cstr);
			free(cstr);
			return result;
		}

		static std::vector<uint8_t> decode_zbase32(const std::string &str) {
			void* out = nullptr;
			size_t out_len = 0;
			if (zbase32_decode(str.c_str(), &out, &out_len) != BASE32_SUCCESS)
				throw std::runtime_error("Crockford decode failed");
			std::vector<uint8_t> result((uint8_t*)out, (uint8_t*)out + out_len);
			free(out);
			return result;
		}

		static std::string encode_base32hex(const void* data, size_t len) {
			char* cstr = base32hex_encode(data, len);
			std::string result(cstr);
			free(cstr);
			return result;
		}

		static std::vector<uint8_t> decode_base32hex(const std::string &str) {
			void* out = nullptr;
			size_t out_len = 0;
			if (base32hex_decode(str.c_str(), &out, &out_len) != BASE32_SUCCESS)
				throw std::runtime_error("Crockford decode failed");
			std::vector<uint8_t> result((uint8_t*)out, (uint8_t*)out + out_len);
			free(out);
			return result;
		}
	};

	class Base64 {
	public:
		// Standard encode/decode
		static std::string encode(const void* data, size_t len) {
			char* cstr = base64_encode(data, len);
			std::string result(cstr);
			free(cstr);
			return result;
		}

		static std::vector<uint8_t> decode(const std::string &str) {
			void* out = nullptr;
			size_t out_len = 0;
			if (base64_decode(str.c_str(), &out, &out_len) != BASE64_SUCCESS)
				throw std::runtime_error("Base64 decode failed");
			std::vector<uint8_t> result((uint8_t*)out, (uint8_t*)out + out_len);
			free(out);
			return result;
		}

		// URL-safe encode/decode
		static std::string encode_url(const void* data, size_t len) {
			char* cstr = base64url_encode(data, len);
			std::string result(cstr);
			free(cstr);
			return result;
		}

		static std::vector<uint8_t> decode_url(const std::string &str) {
			void* out = nullptr;
			size_t out_len = 0;
			if (base64url_decode(str.c_str(), &out, &out_len) != BASE64_SUCCESS)
				throw std::runtime_error("Base64 URL decode failed");
			std::vector<uint8_t> result((uint8_t*)out, (uint8_t*)out + out_len);
			free(out);
			return result;
		}

		// MIME encode/decode
		static std::string encode_mime(const void* data, size_t len) {
			char* cstr = base64mime_encode(data, len);
			std::string result(cstr);
			free(cstr);
			return result;
		}

		static std::vector<uint8_t> decode_mime(const std::string &str) {
			void* out = nullptr;
			size_t out_len = 0;
			if (base64mime_decode(str.c_str(), &out, &out_len) != BASE64_SUCCESS)
				throw std::runtime_error("Base64 MIME decode failed");
			std::vector<uint8_t> result((uint8_t*)out, (uint8_t*)out + out_len);
			free(out);
			return result;
		}

		// Custom encode/decode
		static std::string encode_custom(const void* data, size_t len, const base64_config_t* cfg) {
			char* cstr = base64_encode_custom(data, len, cfg);
			std::string result(cstr);
			free(cstr);
			return result;
		}

		static std::vector<uint8_t> decode_custom(const std::string &str, const base64_config_t* cfg) {
			void* out = nullptr;
			size_t out_len = 0;
			if (base64_decode_custom(str.c_str(), cfg, &out, &out_len) != BASE64_SUCCESS)
				throw std::runtime_error("Base64 custom decode failed");
			std::vector<uint8_t> result((uint8_t*)out, (uint8_t*)out + out_len);
			free(out);
			return result;
		}
	};

	class AES {
	public:
		AES(const void* key, uint32_t keySize) {
			if (AesInitialise(&ctx, key, keySize) != 0)
				throw std::runtime_error("Invalid AES key size");
		}

		~AES() {
			std::memset(&ctx, 0, sizeof(ctx));
		}


		void Encrypt(const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]) const {
			AesEncrypt(&ctx, in, out);
		}

		void Decrypt(const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]) const {
			AesDecrypt(&ctx, in, out);
		}

		void EncryptInPlace(uint8_t block[AES_BLOCK_SIZE]) const {
			AesEncryptInPlace(&ctx, block);
		}

		void DecryptInPlace(uint8_t block[AES_BLOCK_SIZE]) const {
			AesDecryptInPlace(&ctx, block);
		}

		static void xorBuffers(const uint8_t* a, const uint8_t* b, uint8_t* out, uint32_t len) {
			XorBuffers(a, b, out, len);
		}

	private:
		AesContext ctx;
	};


	class AesCbc {
	public:
		AesCbc(const uint8_t* key, uint32_t keySize, const uint8_t iv[AES_BLOCK_SIZE]) {
			if (AesCbcInitialiseWithKey(&ctx, key, keySize, iv) != 0)
				throw std::runtime_error("Invalid key size or IV");
		}

		~AesCbc() {
			std::memset(&ctx, 0, sizeof(ctx));
		}

		// Encrypt a buffer (must be multiple of 16 bytes)
		void encrypt(const void* in, void* out, uint32_t size) {
			if (size % AES_BLOCK_SIZE != 0)
				throw std::runtime_error("Buffer size must be multiple of 16 bytes");
			if (AesCbcEncrypt(&ctx, in, out, size) != 0)
				throw std::runtime_error("CBC encryption failed");
		}

		// Decrypt a buffer (must be multiple of 16 bytes)
		void decrypt(const void* in, void* out, uint32_t size) {
			if (size % AES_BLOCK_SIZE != 0)
				throw std::runtime_error("Buffer size must be multiple of 16 bytes");
			if (AesCbcDecrypt(&ctx, in, out, size) != 0)
				throw std::runtime_error("CBC decryption failed");
		}

		// One-shot static helpers
		static std::vector<uint8_t> encryptWithKey(const std::vector<uint8_t>& key, const std::array<uint8_t, AES_BLOCK_SIZE>& iv, const std::vector<uint8_t>& data) {
			if (key.size() > UINT32_MAX) throw std::length_error("input too large");
			if (data.size() > UINT32_MAX) throw std::length_error("input too large");
			if (data.size() % AES_BLOCK_SIZE != 0)
				throw std::runtime_error("Data size must be multiple of 16 bytes");
			std::vector<uint8_t> out(data.size());
			if (AesCbcEncryptWithKey(key.data(), static_cast<uint32_t>(key.size()), iv.data(), data.data(), out.data(), static_cast<uint32_t>(data.size())) != 0)
				throw std::runtime_error("CBC encryption with key failed");
			return out;
		}

		static std::vector<uint8_t> decryptWithKey(const std::vector<uint8_t>& key, const std::array<uint8_t, AES_BLOCK_SIZE>& iv, const std::vector<uint8_t>& data) {
			if (key.size() > UINT32_MAX) throw std::length_error("input too large");
			if (data.size() > UINT32_MAX) throw std::length_error("input too large");
			if (data.size() % AES_BLOCK_SIZE != 0)
				throw std::runtime_error("Data size must be multiple of 16 bytes");
			std::vector<uint8_t> out(data.size());
			if (AesCbcDecryptWithKey(key.data(), static_cast<uint32_t>(key.size()), iv.data(), data.data(), out.data(), static_cast<uint32_t>(data.size())) != 0)
				throw std::runtime_error("CBC decryption with key failed");
			return out;
		}

	private:
		AesCbcContext ctx;
	};

	class AesCtr {
	public:
		// Initialize with key + IV
		AesCtr(const uint8_t* key, uint32_t keySize, const uint8_t iv[AES_CTR_IV_SIZE]) {
			if (AesCtrInitialiseWithKey(&ctx, key, keySize, iv) != 0)
				throw std::runtime_error("Invalid AES key size");
		}

		~AesCtr() {
			std::memset(&ctx, 0, sizeof(ctx));
		}

		// Set stream index (random access)
		void setStreamIndex(uint64_t index) {
			AesCtrSetStreamIndex(&ctx, index);
		}

		// Encrypt/decrypt in-place
		void xorStream(const void* in, void* out, uint32_t size) {
			AesCtrXor(&ctx, in, out, size);
		}

		// Generate keystream bytes
		void outputKeystream(void* out, uint32_t size) {
			AesCtrOutput(&ctx, out, size);
		}

		// One-shot encryption/decryption
		static std::vector<uint8_t> xorWithKey(const std::vector<uint8_t>& key,
						       const std::array<uint8_t, AES_CTR_IV_SIZE>& iv,
						       const std::vector<uint8_t>& data) {
			if (key.size() > UINT32_MAX) throw std::length_error("input too large");
			if (data.size() > UINT32_MAX) throw std::length_error("input too large");
			std::vector<uint8_t> out(data.size());
			if (AesCtrXorWithKey(key.data(), static_cast<uint32_t>(key.size()), iv.data(), data.data(), out.data(), static_cast<uint32_t>(data.size())) != 0)
				throw std::runtime_error("AES-CTR one-shot XOR failed");
			return out;
		}

	private:
		AesCtrContext ctx;
	};

	class AesOfb {
	public:
		// Initialize with key + IV
		AesOfb(const uint8_t* key, uint32_t keySize, const uint8_t iv[AES_BLOCK_SIZE]) {
			if (AesOfbInitialiseWithKey(&ctx, key,keySize, iv) != 0)
				throw std::runtime_error("Invalid AES key size");
		}

		~AesOfb() {
			std::memset(&ctx, 0, sizeof(ctx));
		}

		// XOR buffer (in-place or separate output)
		void xorStream(const void* in, void* out, uint32_t size) {
			AesOfbXor(&ctx, in, out, size);
		}

		// Output raw OFB keystream
		void outputKey(void* out, uint32_t size) {
			AesOfbOutput(&ctx, out,size);
		}

		// One-shot XOR
		static std::vector<uint8_t> xorWithKey(const std::vector<uint8_t>& key,
						       const std::array<uint8_t, AES_BLOCK_SIZE>& iv,
						       const std::vector<uint8_t>& data) {
			std::vector<uint8_t> out(data.size());
			if (AesOfbXorWithKey(key.data(), static_cast<uint32_t>(key.size()), iv.data(),
								 data.data(), out.data(), static_cast<uint32_t>(data.size())) != 0)
				throw std::runtime_error("AES-OFB one-shot XOR failed");
			return out;
		}

	private:
		AesOfbContext ctx;
	};

	class CRC32 {
	public:
		enum class Variant {
			IEEE,	// Default IEEE 802.3 CRC-32
			CRC32C,	// Castagnoli
			CRC32K,	// Koopman
			CRC32Q,
			CRC32D,
			XFER,
			AUTOSAR
		};

		CRC32(Variant variant = Variant::IEEE, bool reflected = true)
			: reflected_(reflected) {
			uint32_t poly = getPolynomial(variant, reflected_);
			if (reflected_) {
				crc32_reflected_table(table_.data(), poly);
			} else {
				crc32_init_table(table_.data(), poly);
			}
		}

		uint32_t compute(const void* data, size_t len, uint32_t init_crc = 0xFFFFFFFF) const {
			if (reflected_) {
				return ccrc32_reflected(init_crc, data, len, table_.data());
			} else {
				return ccrc32(init_crc, data, len, table_.data());
			}
		}

		uint32_t compute(const std::vector<uint8_t>& data, uint32_t init_crc = 0xFFFFFFFF) const {
			return compute(data.data(), data.size(), init_crc);
		}

		uint32_t compute(const std::string& str, uint32_t init_crc = 0xFFFFFFFF) const {
			return compute(reinterpret_cast<const uint8_t*>(str.data()), str.size(), init_crc);
		}

	private:
		std::array<uint32_t, 256> table_;
		bool reflected_;

		static uint32_t getPolynomial(Variant v, bool reflected) {
			switch (v) {
				case Variant::IEEE: return reflected ? CRC32_POLY_REFLECTED : CRC32_POLY;
				case Variant::CRC32C: return reflected ? CRC32C_POLY_REFLECTED : CRC32C_POLY;
				case Variant::CRC32K: return reflected ? CRC32K_POLY_REFLECTED : CRC32K_POLY;
				case Variant::CRC32Q: return reflected ? CRC32Q_POLY_REFLECTED : CRC32Q_POLY;
				case Variant::CRC32D: return reflected ? CRC32D_POLY_REFLECTED : CRC32D_POLY;
				case Variant::XFER: return reflected ? CRC32_XFER_POLY_REFLECTED : CRC32_XFER_POLY;
				case Variant::AUTOSAR: return reflected ? CRC32_AUTOSAR_POLY_REFLECTED : CRC32_AUTOSAR_POLY;
				default: throw std::runtime_error("Unknown CRC32 variant");
			}
		}
	};

	class CRC32Ext : public CRC32 {
	public:
		enum class Variant {
			IEEE,
			CRC32C,
			CRC32K,
			CRC32Q,
			CRC32D,
			XFER,
			AUTOSAR
		};

		// Memory-based CRC
		static uint32_t compute(const void* data, size_t len, Variant v = Variant::IEEE) {
			switch (v) {
				case Variant::IEEE: return crc32_ieee(data, len);
				case Variant::CRC32C: return crc32c(data, len);
				case Variant::CRC32K: return crc32k(data, len);
				case Variant::CRC32Q: return crc32q(data, len);
				case Variant::CRC32D: return crc32d(data, len);
				case Variant::XFER: return crc32_xfer(data, len);
				case Variant::AUTOSAR: return crc32_autosar(data, len);
				default: throw std::runtime_error("Unknown CRC32 variant");
			}
		}

		static uint32_t compute(const std::vector<uint8_t>& data, Variant v = Variant::IEEE) {
			return compute(data.data(), data.size(), v);
		}

		static uint32_t compute(const std::string& str, Variant v = Variant::IEEE) {
			return compute(reinterpret_cast<const uint8_t*>(str.data()), str.size(), v);
		}

		// File-based CRC
		static uint32_t compute_file(const std::string& path, Variant v = Variant::IEEE) {
			switch (v) {
				case Variant::IEEE: return crc32_ieee_file(path.c_str());
				case Variant::CRC32C: return crc32c_file(path.c_str());
				case Variant::CRC32K: return crc32k_file(path.c_str());
				case Variant::CRC32Q: return crc32q_file(path.c_str());
				case Variant::CRC32D: return crc32d_file(path.c_str());
				case Variant::XFER: return crc32_xfer_file(path.c_str());
				case Variant::AUTOSAR: return crc32_autosar_file(path.c_str());
				default: throw std::runtime_error("Unknown CRC32 variant");
			}
		}
	};

	class Rc4 {
	public:
		Rc4(const void* key, uint32_t keySize, uint32_t dropN = 0) {
			if (!key && keySize > 0)
				throw std::invalid_argument("RC4 key pointer is null");

			Rc4Initialise(&ctx, key, keySize, dropN);
		}

		~Rc4() {
			std::memset(&ctx, 0, sizeof(ctx));
		}

		Rc4(const Rc4&) = delete;
		Rc4& operator=(const Rc4&) = delete;
		Rc4(Rc4&&) = delete;
		Rc4& operator=(Rc4&&) = delete;

		// Generate keystream bytes
		void output(void* out, uint32_t size) {
			if (!out && size > 0)
				throw std::invalid_argument("Output buffer is null");
			Rc4Output(&ctx, out, size);
		}

		// XOR buffer with keystream
		void xorStream(const void* in, void* out, uint32_t size) {
			if (size > 0) {
				if (!out) throw std::invalid_argument("Output buffer is null");
				if (!in)  throw std::invalid_argument("Input buffer is null");
			}
			Rc4Xor(&ctx, in, out, size);
		}

	private:
		Rc4Context ctx;
	};

}

#endif // HASH_HPP
