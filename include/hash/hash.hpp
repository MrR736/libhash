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
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>
#include <cstdlib>

#include "hash.h"

namespace hash {

// Internal utilities
namespace detail {
	inline std::uint32_t checked_u32(std::size_t size) {
		if (size > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
			throw std::length_error("input too large");
		}
		return static_cast<std::uint32_t>(size);
	}

	inline void secure_zero(void* data, std::size_t size) noexcept {
		if (!data || size == 0) return;
		volatile std::uint8_t* p = static_cast<volatile std::uint8_t*>(data);
		while (size--) *p++ = 0;
	}

	inline std::vector<std::uint8_t> make_vector(void* data, std::size_t size) {
		if (size == 0) {
			std::free(data);
			return std::vector<std::uint8_t>();
		}
		if (!data) throw std::runtime_error("C library returned null data");
		std::uint8_t* begin = static_cast<std::uint8_t*>(data);
		std::vector<std::uint8_t> result(begin,begin + size);
		std::free(data);
		return result;
	}
} // namespace detail

//MD2
class Md2 {
public:
	typedef MD2_HASH digest_type;

	Md2() : finalized_(false) {
		Md2Initialise(&ctx_);
	}

	Md2(const Md2&) = delete;
	Md2& operator=(const Md2&) = delete;

	Md2(Md2&&) = delete;
	Md2& operator=(Md2&&) = delete;

	~Md2() noexcept {
		detail::secure_zero(&ctx_, sizeof(ctx_));
		detail::secure_zero(&digest_, sizeof(digest_));
	}

	void update(const void* data,std::size_t size) {
		Md2Update(&ctx_,data,detail::checked_u32(size));
		finalized_ = false;
	}

	void update(const std::vector<std::uint8_t>& data) {
		update(data.data(), data.size());
	}

	void update(const std::string& text) {
		update(text.data(), text.size());
	}

	digest_type& finalize() {
		Md2Finalise(&ctx_, &digest_);
		finalized_ = true;
		return digest_;
	}

	const digest_type& digest() const noexcept {
		return digest_;
	}

	bool finalized() const noexcept {
		return finalized_;
	}

	static digest_type calculate(const void* data,std::size_t size) {
		digest_type result{};
		Md2Calculate(data,detail::checked_u32(size),&result);
		return result;
	}

	static digest_type calculate(const std::vector<std::uint8_t>& data) {
		return calculate(data.data(),data.size());
	}

	static digest_type calculate(const std::string& text) {
		return calculate(text.data(),text.size());
	}

private:
	Md2Context ctx_;
	digest_type digest_;
	bool finalized_;
};

//MD4
class Md4 {
public:
	typedef MD4_HASH digest_type;

	Md4() : finalized_(false) {
		Md4Initialise(&ctx_);
	}

	Md4(const Md4&) = delete;
	Md4& operator=(const Md4&) = delete;

	Md4(Md4&&) = delete;
	Md4& operator=(Md4&&) = delete;

	~Md4() noexcept {
		detail::secure_zero(&ctx_, sizeof(ctx_));
		detail::secure_zero(&digest_, sizeof(digest_));
	}

	void update(const void* data,std::size_t size) {
		Md4Update(&ctx_,data,detail::checked_u32(size));
		finalized_ = false;
	}

	void update(const std::vector<std::uint8_t>& data) {
		update(data.data(), data.size());
	}

	void update(const std::string& text) {
		update(text.data(), text.size());
	}

	digest_type& finalize() {
		Md4Finalise(&ctx_, &digest_);
		finalized_ = true;
		return digest_;
	}

	const digest_type& digest() const noexcept {
		return digest_;
	}

	bool finalized() const noexcept {
		return finalized_;
	}

	static digest_type calculate(const void* data,std::size_t size) {
		digest_type result{};
		Md4Calculate(data,detail::checked_u32(size),&result);
		return result;
	}

	static digest_type calculate(const std::vector<std::uint8_t>& data) {
		return calculate(data.data(),data.size());
	}

	static digest_type calculate(const std::string& text) {
		return calculate(text.data(),text.size());
	}

private:
	Md4Context ctx_;
	digest_type digest_;
	bool finalized_;
};

//MD5
class Md5 {
public:
	typedef MD5_HASH digest_type;

	Md5() : finalized_(false) {
		Md5Initialise(&ctx_);
	}

	Md5(const Md5&) = delete;
	Md5& operator=(const Md5&) = delete;

	Md5(Md5&&) = delete;
	Md5& operator=(Md5&&) = delete;

	~Md5() noexcept {
		detail::secure_zero(&ctx_, sizeof(ctx_));
		detail::secure_zero(&digest_, sizeof(digest_));
	}

	void update(const void* data,std::size_t size) {
		Md5Update(&ctx_,data,detail::checked_u32(size));
		finalized_ = false;
	}

	void update(const std::vector<std::uint8_t>& data) {
		update(data.data(), data.size());
	}

	void update(const std::string& text) {
		update(text.data(), text.size());
	}

	digest_type& finalize() {
		Md5Finalise(&ctx_, &digest_);
		finalized_ = true;
		return digest_;
	}

	const digest_type& digest() const noexcept {
		return digest_;
	}

	bool finalized() const noexcept {
		return finalized_;
	}

	static digest_type calculate(const void* data,std::size_t size) {
		digest_type result{};
		Md5Calculate(data,detail::checked_u32(size),&result);
		return result;
	}

	static digest_type calculate(const std::vector<std::uint8_t>& data) {
		return calculate(data.data(),data.size());
	}

	static digest_type calculate(const std::string& text) {
		return calculate(text.data(),text.size());
	}

private:
	Md5Context ctx_;
	digest_type digest_;
	bool finalized_;
};

// SHA-0
class Sha0 {
public:
	typedef SHA0_HASH digest_type;

	Sha0() : finalized_(false) {
		Sha0Initialise(&ctx_);
	}

	Sha0(const Sha0&) = delete;
	Sha0& operator=(const Sha0&) = delete;

	Sha0(Sha0&&) = delete;
	Sha0& operator=(Sha0&&) = delete;

	~Sha0() noexcept {
		detail::secure_zero(&ctx_, sizeof(ctx_));
		detail::secure_zero(&digest_, sizeof(digest_));
	}

	void update(const void* data,std::size_t size) {
		Sha0Update(&ctx_,data,detail::checked_u32(size));
		finalized_ = false;
	}

	void update(const std::vector<std::uint8_t>& data) {
		update(data.data(), data.size());
	}

	void update(const std::string& text) {
		update(text.data(), text.size());
	}

	digest_type& finalize() {
		Sha0Finalise(&ctx_, &digest_);
		finalized_ = true;
		return digest_;
	}

	const digest_type& digest() const noexcept {
		return digest_;
	}

	bool finalized() const noexcept {
		return finalized_;
	}

	static digest_type calculate(const void* data,std::size_t size) {
		digest_type result{};
		Sha0Calculate(data,detail::checked_u32(size),&result);
		return result;
	}

	static digest_type calculate(const std::vector<std::uint8_t>& data){
		return calculate(data.data(),data.size());
	}

	static digest_type calculate(const std::string& text) {
		return calculate(text.data(),text.size());
	}

private:
	Sha0Context ctx_;
	digest_type digest_;
	bool finalized_;
};

// SHA-1
class Sha1 {
public:
	typedef SHA1_HASH digest_type;

	Sha1() : finalized_(false) {
		Sha1Initialise(&ctx_);
	}

	Sha1(const Sha1&) = delete;
	Sha1& operator=(const Sha1&) = delete;

	Sha1(Sha1&&) = delete;
	Sha1& operator=(Sha1&&) = delete;

	~Sha1() noexcept {
		detail::secure_zero(&ctx_, sizeof(ctx_));
		detail::secure_zero(&digest_, sizeof(digest_));
	}

	void update(const void* data,std::size_t size) {
		Sha1Update(&ctx_,data,detail::checked_u32(size));
		finalized_ = false;
	}

	void update(const std::vector<std::uint8_t>& data) {
		update(data.data(), data.size());
	}

	void update(const std::string& text) {
		update(text.data(), text.size());
	}

	digest_type& finalize() {
		Sha1Finalise(&ctx_, &digest_);
		finalized_ = true;
		return digest_;
	}

	const digest_type& digest() const noexcept {
		return digest_;
	}

	bool finalized() const noexcept {
		return finalized_;
	}

	static digest_type calculate(const void* data,std::size_t size) {
		digest_type result{};
		Sha1Calculate(data,detail::checked_u32(size),&result);
		return result;
	}

	static digest_type calculate(const std::vector<std::uint8_t>& data){
		return calculate(data.data(),data.size());
	}

	static digest_type calculate(const std::string& text) {
		return calculate(text.data(),text.size());
	}

private:
	Sha1Context ctx_;
	digest_type digest_;
	bool finalized_;
};

// SHA-224
class Sha224 {
public:
	typedef SHA224_HASH digest_type;

	Sha224() : finalized_(false) {
		Sha224Initialise(&ctx_);
	}

	Sha224(const Sha224&) = delete;
	Sha224& operator=(const Sha224&) = delete;

	Sha224(Sha224&&) = delete;
	Sha224& operator=(Sha224&&) = delete;

	~Sha224() noexcept {
		detail::secure_zero(&ctx_, sizeof(ctx_));
		detail::secure_zero(&digest_, sizeof(digest_));
	}

	void update(const void* data,std::size_t size) {
		Sha224Update(&ctx_,data,detail::checked_u32(size));
		finalized_ = false;
	}

	void update(const std::vector<std::uint8_t>& data) {
		update(data.data(), data.size());
	}

	void update(const std::string& text) {
		update(text.data(), text.size());
	}

	digest_type& finalize() {
		Sha224Finalise(&ctx_, &digest_);
		finalized_ = true;
		return digest_;
	}

	const digest_type& digest() const noexcept {
		return digest_;
	}

	bool finalized() const noexcept {
		return finalized_;
	}

	static digest_type calculate(const void* data,std::size_t size) {
		digest_type result{};
		Sha224Calculate(data,detail::checked_u32(size),&result);
		return result;
	}

	static digest_type calculate(const std::vector<std::uint8_t>& data) {
		return calculate(data.data(),data.size());
	}

	static digest_type calculate(const std::string& text) {
		return calculate(text.data(),text.size());
	}

private:
	Sha224Context ctx_;
	digest_type digest_;
	bool finalized_;
};

// SHA-256
class Sha256 {
public:
	typedef SHA256_HASH digest_type;

	Sha256() : finalized_(false) {
		Sha256Initialise(&ctx_);
	}

	Sha256(const Sha256&) = delete;
	Sha256& operator=(const Sha256&) = delete;

	Sha256(Sha256&&) = delete;
	Sha256& operator=(Sha256&&) = delete;

	~Sha256() noexcept {
		detail::secure_zero(&ctx_, sizeof(ctx_));
		detail::secure_zero(&digest_, sizeof(digest_));
	}

	void update(const void* data,std::size_t size) {
		Sha256Update(&ctx_,data,detail::checked_u32(size));
		finalized_ = false;
	}

	void update(const std::vector<std::uint8_t>& data) {
		update(data.data(), data.size());
	}

	void update(const std::string& text) {
		update(text.data(), text.size());
	}

	digest_type& finalize() {
		Sha256Finalise(&ctx_, &digest_);
		finalized_ = true;
		return digest_;
	}

	const digest_type& digest() const noexcept {
		return digest_;
	}

	bool finalized() const noexcept {
		return finalized_;
	}

	static digest_type calculate(const void* data,std::size_t size) {
		digest_type result{};
		Sha256Calculate(data,detail::checked_u32(size),&result);
		return result;
	}

	static digest_type calculate(const std::vector<std::uint8_t>& data) {
		return calculate(data.data(),data.size());
	}

	static digest_type calculate(const std::string& text) {
		return calculate(text.data(),text.size());
	}

private:
	Sha256Context ctx_;
	digest_type digest_;
	bool finalized_;
};

// SHA-384
class Sha384 {
public:
	typedef SHA384_HASH digest_type;

	Sha384() : finalized_(false) {
		Sha384Initialise(&ctx_);
	}

	Sha384(const Sha384&) = delete;
	Sha384& operator=(const Sha384&) = delete;

	Sha384(Sha384&&) = delete;
	Sha384& operator=(Sha384&&) = delete;

	~Sha384() noexcept {
		detail::secure_zero(&ctx_, sizeof(ctx_));
		detail::secure_zero(&digest_, sizeof(digest_));
	}

	void update(const void* data,std::size_t size) {
		Sha384Update(&ctx_,data,detail::checked_u32(size));
		finalized_ = false;
	}

	void update(const std::vector<std::uint8_t>& data) {
		update(data.data(), data.size());
	}

	void update(const std::string& text) {
		update(text.data(), text.size());
	}

	digest_type& finalize() {
		Sha384Finalise(&ctx_, &digest_);
		finalized_ = true;
		return digest_;
	}

	const digest_type& digest() const noexcept {
		return digest_;
	}

	bool finalized() const noexcept {
		return finalized_;
	}

	static digest_type calculate(const void* data,std::size_t size) {
		digest_type result{};
		Sha384Calculate(data,detail::checked_u32(size),&result);
		return result;
	}

	static digest_type calculate(const std::vector<std::uint8_t>& data) {
		return calculate(data.data(),data.size());
	}

	static digest_type calculate(const std::string& text) {
		return calculate(text.data(),text.size());
	}

private:
	Sha384Context ctx_;
	digest_type digest_;
	bool finalized_;
};

// SHA-3_256
class Sha3_256 {
public:
	typedef SHA3_256_HASH digest_type;

	Sha3_256() : finalized_(false) {
		Sha3_256Initialise(&ctx_);
	}

	Sha3_256(const Sha3_256&) = delete;
	Sha3_256& operator=(const Sha3_256&) = delete;

	Sha3_256(Sha3_256&&) = delete;
	Sha3_256& operator=(Sha3_256&&) = delete;

	~Sha3_256() noexcept {
		detail::secure_zero(&ctx_, sizeof(ctx_));
		detail::secure_zero(&digest_, sizeof(digest_));
	}

	void update(const void* data,std::size_t size) {
		Sha3_256Update(&ctx_,data,detail::checked_u32(size));
		finalized_ = false;
	}

	void update(const std::vector<std::uint8_t>& data) {
		update(data.data(), data.size());
	}

	void update(const std::string& text) {
		update(text.data(), text.size());
	}

	digest_type& finalize() {
		Sha3_256Finalise(&ctx_, &digest_);
		finalized_ = true;
		return digest_;
	}

	const digest_type& digest() const noexcept {
		return digest_;
	}

	bool finalized() const noexcept {
		return finalized_;
	}

	static digest_type calculate(const void* data,std::size_t size) {
		digest_type result{};
		Sha3_256Calculate(data,detail::checked_u32(size),&result);
		return result;
	}

	static digest_type calculate(const std::vector<std::uint8_t>& data) {
		return calculate(data.data(),data.size());
	}

	static digest_type calculate(const std::string& text) {
		return calculate(text.data(),text.size());
	}

private:
	Sha3_256Context ctx_;
	digest_type digest_;
	bool finalized_;
};

// SHA-3_512
class Sha3_512 {
public:
	typedef SHA3_512_HASH digest_type;

	Sha3_512() : finalized_(false) {
		Sha3_512Initialise(&ctx_);
	}

	Sha3_512(const Sha3_512&) = delete;
	Sha3_512& operator=(const Sha3_512&) = delete;

	Sha3_512(Sha3_512&&) = delete;
	Sha3_512& operator=(Sha3_512&&) = delete;

	~Sha3_512() noexcept {
		detail::secure_zero(&ctx_, sizeof(ctx_));
		detail::secure_zero(&digest_, sizeof(digest_));
	}

	void update(const void* data,std::size_t size) {
		Sha3_512Update(&ctx_,data,detail::checked_u32(size));
		finalized_ = false;
	}

	void update(const std::vector<std::uint8_t>& data) {
		update(data.data(), data.size());
	}

	void update(const std::string& text) {
		update(text.data(), text.size());
	}

	digest_type& finalize() {
		Sha3_512Finalise(&ctx_, &digest_);
		finalized_ = true;
		return digest_;
	}

	const digest_type& digest() const noexcept {
		return digest_;
	}

	bool finalized() const noexcept {
		return finalized_;
	}

	static digest_type calculate(const void* data,std::size_t size) {
		digest_type result{};
		Sha3_512Calculate(data,detail::checked_u32(size),&result);
		return result;
	}

	static digest_type calculate(const std::vector<std::uint8_t>& data) {
		return calculate(data.data(),data.size());
	}

	static digest_type calculate(const std::string& text) {
		return calculate(text.data(),text.size());
	}

private:
	Sha3_512Context ctx_;
	digest_type digest_;
	bool finalized_;
};

// SHA-512
class Sha512 {
public:
	typedef SHA512_HASH digest_type;

	Sha512() : finalized_(false) {
		Sha512Initialise(&ctx_);
	}

	Sha512(const Sha512&) = delete;
	Sha512& operator=(const Sha512&) = delete;

	Sha512(Sha512&&) = delete;
	Sha512& operator=(Sha512&&) = delete;

	~Sha512() noexcept {
		detail::secure_zero(&ctx_, sizeof(ctx_));
		detail::secure_zero(&digest_, sizeof(digest_));
	}

	void update(const void* data,std::size_t size) {
		Sha512Update(&ctx_,data,detail::checked_u32(size));
		finalized_ = false;
	}

	void update(const std::vector<std::uint8_t>& data) {
		update(data.data(), data.size());
	}

	void update(const std::string& text) {
		update(text.data(), text.size());
	}

	digest_type& finalize() {
		Sha512Finalise(&ctx_, &digest_);
		finalized_ = true;
		return digest_;
	}

	const digest_type& digest() const noexcept {
		return digest_;
	}

	bool finalized() const noexcept {
		return finalized_;
	}

	static digest_type calculate(const void* data,std::size_t size) {
		digest_type result{};
		Sha512Calculate(data,detail::checked_u32(size),&result);
		return result;
	}

	static digest_type calculate(const std::vector<std::uint8_t>& data) {
		return calculate(data.data(),data.size());
	}

	static digest_type calculate(const std::string& text) {
		return calculate(text.data(),text.size());
	}

private:
	Sha512Context ctx_;
	digest_type digest_;
	bool finalized_;
};

// SHA-512_224
class Sha512_224 {
public:
	typedef SHA512_224_HASH digest_type;

	Sha512_224() : finalized_(false) {
		Sha512_224Initialise(&ctx_);
	}

	Sha512_224(const Sha512_224&) = delete;
	Sha512_224& operator=(const Sha512_224&) = delete;

	Sha512_224(Sha512_224&&) = delete;
	Sha512_224& operator=(Sha512_224&&) = delete;

	~Sha512_224() noexcept {
		detail::secure_zero(&ctx_, sizeof(ctx_));
		detail::secure_zero(&digest_, sizeof(digest_));
	}

	void update(const void* data,std::size_t size) {
		Sha512_224Update(&ctx_,data,detail::checked_u32(size));
		finalized_ = false;
	}

	void update(const std::vector<std::uint8_t>& data) {
		update(data.data(), data.size());
	}

	void update(const std::string& text) {
		update(text.data(), text.size());
	}

	digest_type& finalize() {
		Sha512_224Finalise(&ctx_, &digest_);
		finalized_ = true;
		return digest_;
	}

	const digest_type& digest() const noexcept {
		return digest_;
	}

	bool finalized() const noexcept {
		return finalized_;
	}

	static digest_type calculate(const void* data,std::size_t size) {
		digest_type result{};
		Sha512_224Calculate(data,detail::checked_u32(size),&result);
		return result;
	}

	static digest_type calculate(const std::vector<std::uint8_t>& data) {
		return calculate(data.data(),data.size());
	}

	static digest_type calculate(const std::string& text) {
		return calculate(text.data(),text.size());
	}

private:
	Sha512_224Context ctx_;
	digest_type digest_;
	bool finalized_;
};

// SHA-512_256
class Sha512_256 {
public:
	typedef SHA512_256_HASH digest_type;

	Sha512_256() : finalized_(false) {
		Sha512_256Initialise(&ctx_);
	}

	Sha512_256(const Sha512_256&) = delete;
	Sha512_256& operator=(const Sha512_256&) = delete;

	Sha512_256(Sha512_256&&) = delete;
	Sha512_256& operator=(Sha512_256&&) = delete;

	~Sha512_256() noexcept {
		detail::secure_zero(&ctx_, sizeof(ctx_));
		detail::secure_zero(&digest_, sizeof(digest_));
	}

	void update(const void* data,std::size_t size) {
		Sha512_256Update(&ctx_,data,detail::checked_u32(size));
		finalized_ = false;
	}

	void update(const std::vector<std::uint8_t>& data) {
		update(data.data(), data.size());
	}

	void update(const std::string& text) {
		update(text.data(), text.size());
	}

	digest_type& finalize() {
		Sha512_256Finalise(&ctx_, &digest_);
		finalized_ = true;
		return digest_;
	}

	const digest_type& digest() const noexcept {
		return digest_;
	}

	bool finalized() const noexcept {
		return finalized_;
	}

	static digest_type calculate(const void* data,std::size_t size) {
		digest_type result{};
		Sha512_256Calculate(data,detail::checked_u32(size),&result);
		return result;
	}

	static digest_type calculate(const std::vector<std::uint8_t>& data) {
		return calculate(data.data(),data.size());
	}

	static digest_type calculate(const std::string& text) {
		return calculate(text.data(),text.size());
	}

private:
	Sha512_256Context ctx_;
	digest_type digest_;
	bool finalized_;
};

// Base16
class Base16 {
public:
	static std::string encode(const void* data,std::size_t size,bool uppercase = false) {
		char* result = base16_encode(data,size,uppercase ? 1 : 0);
		if (!result) throw std::runtime_error("base16 encoding failed");
		std::string output(result);
		std::free(result);
		return output;
	}

	static std::string encode(const std::vector<std::uint8_t>& data,bool uppercase = false) {
		return encode(data.data(),data.size(),uppercase);
	}

	static std::string encode(const std::string& text,bool uppercase = false) {
		return encode(text.data(),text.size(),uppercase);
	}

	static std::vector<std::uint8_t> decode(const std::string& text,bool uppercase = false) {
		void* output = NULL;
		std::size_t output_size = 0;
		const int rc = base16_decode(text.c_str(),&output,&output_size,uppercase ? 1 : 0);
		if (rc != 0) {
			std::free(output);
			throw std::runtime_error("base16 decoding failed");
		}
		return detail::make_vector(output,output_size);
	}

	static std::string encode_custom(const void* data,std::size_t size,const base16_config_t& config) {
		char* result = base16_encode_custom(data,size,&config);
		if (!result) throw std::runtime_error("base16 custom encoding failed");
		std::string output(result);
		std::free(result);
		return output;
	}

	static std::string encode_custom(const std::vector<std::uint8_t>& data,const base16_config_t& config) {
		return encode_custom(data.data(),data.size(),config);
	}

	static std::string encode_custom(const std::string& text,const base16_config_t& config) {
		return encode_custom(text.data(),text.size(),config);
	}

	static std::vector<std::uint8_t> decode_custom(const std::string& text,const base16_config_t& config) {
		void* output = NULL;
		std::size_t output_size = 0;
		const int rc = base16_decode_custom(text.c_str(),&config,&output,&output_size);
		if (rc != 0) {
			std::free(output);
			throw std::runtime_error("base16 custom decoding failed");
		}
		return detail::make_vector(output,output_size);
	}
};

// Base32
class Base32 {
public:
	static std::string encode(const void* data,std::size_t size) {
		char* result = base32_encode(data, size);
		if (!result) throw std::runtime_error("base32 encoding failed");
		std::string output(result);
		std::free(result);
		return output;
	}

	static std::string encode(const std::vector<std::uint8_t>& data) {
		return encode(data.data(),data.size());
	}

	static std::string encode(const std::string& text) {
		return encode(text.data(),text.size());
	}

	static std::vector<std::uint8_t> decode(const std::string& text) {
		void* output = NULL;
		std::size_t output_size = 0;
		const int rc = base32_decode(text.c_str(),&output,&output_size);
		if (rc != BASE32_SUCCESS) {
			std::free(output);
			throw std::runtime_error("base32 decoding failed");
		}
		return detail::make_vector(output,output_size);
	}

	static std::string encode_custom(const void* data,std::size_t size,const base32_config_t& config) {
		char* result = base32_encode_custom(data,size,&config);
		if (!result) throw std::runtime_error("base32 custom encoding failed");
		std::string output(result);
		std::free(result);
		return output;
	}

	static std::string encode_custom(const std::vector<std::uint8_t>& data,const base32_config_t& config) {
		return encode_custom(data.data(),data.size(),config);
	}

	static std::string encode_custom(const std::string& text,const base32_config_t& config) {
		return encode_custom(text.data(),text.size(),config);
	}

	static std::vector<std::uint8_t> decode_custom(const std::string& text,const base32_config_t& config) {
		void* output = NULL;
		std::size_t output_size = 0;

		const int rc = base32_decode_custom(text.c_str(),&config,&output,&output_size);

		if (rc != BASE32_SUCCESS) {
			std::free(output);
			throw std::runtime_error("base32 custom decoding failed");
		}
		return detail::make_vector(output,output_size);
	}

	static std::string encode_crockford(const void* data,std::size_t size) {
		char* result = crockford_base32_encode(data,size);
		if (!result) throw std::runtime_error("Crockford base32 encoding failed");
		std::string output(result);
		std::free(result);
		return output;
	}

	static std::string encode_crockford(const std::vector<std::uint8_t>& data) {
		return encode_crockford(data.data(),data.size());
	}

	static std::string encode_crockford(const std::string& text) {
		return encode_crockford(text.data(),text.size());
	}

	static std::vector<std::uint8_t> decode_crockford(const std::string& text) {
		void* output = NULL;
		std::size_t output_size = 0;
		const int rc = crockford_base32_decode(text.c_str(),&output,&output_size);
		if (rc != BASE32_SUCCESS) {
			std::free(output);
			throw std::runtime_error("Crockford base32 decoding failed");
		}
		return detail::make_vector(output,output_size);
	}

	static std::string encode_zbase32(const void* data,std::size_t size) {
		char* result = zbase32_encode(data, size);
		if (!result) throw std::runtime_error("z-base-32 encoding failed");
		std::string output(result);
		std::free(result);
		return output;
	}

	static std::string encode_zbase32(const std::vector<std::uint8_t>& data) {
		return encode_zbase32(data.data(),data.size());
	}

	static std::string encode_zbase32(const std::string& text) {
		return encode_zbase32(text.data(),text.size());
	}

	static std::vector<std::uint8_t> decode_zbase32(const std::string& text) {
		void* output = NULL;
		std::size_t output_size = 0;
		const int rc = zbase32_decode(text.c_str(),&output,&output_size);
		if (rc != BASE32_SUCCESS) {
			std::free(output);
			throw std::runtime_error("z-base-32 decoding failed");
		}
		return detail::make_vector(output,output_size);
	}

	static std::string encode_hex(const void* data,std::size_t size) {
		char* result = base32hex_encode(data, size);
		if (!result) throw std::runtime_error("base32hex encoding failed");
		std::string output(result);
		std::free(result);
		return output;
	}

	static std::string encode_hex(const std::vector<std::uint8_t>& data) {
		return encode_hex(data.data(),data.size());
	}

	static std::string encode_hex(const std::string& text) {
		return encode_hex(text.data(),text.size());
	}

	static std::vector<std::uint8_t> decode_hex(const std::string& text) {
		void* output = NULL;
		std::size_t output_size = 0;
		const int rc = base32hex_decode(text.c_str(),&output,&output_size);
		if (rc != BASE32_SUCCESS) {
			std::free(output);
			throw std::runtime_error("base32hex decoding failed");
		}

		return detail::make_vector(output,output_size);
	}
};

// Base58
class Base58 {
public:
	static std::string encode(const void* data,std::size_t size) {
		char* result = base58_encode(data, size);
		if (!result)throw std::runtime_error("base58 encoding failed");
		std::string output(result);
		std::free(result);
		return output;
	}

	static std::string encode(const std::vector<std::uint8_t>& data){
		return encode(data.data(),data.size());
	}

	static std::string encode(const std::string& text){
		return encode(text.data(),text.size());
	}

	static std::vector<std::uint8_t> decode(const std::string& text) {
		void* output = NULL;
		std::size_t output_size = 0;
		const int rc = base58_decode(text.c_str(),&output,&output_size);
		if (rc != BASE58_SUCCESS) {
			std::free(output);
			throw std::runtime_error("base58 decoding failed");
		}
		return detail::make_vector(output,output_size);
	}

	static std::string encode_bitcoin(const void* data,std::size_t size) {
		char* result = base58btc_encode(data, size);
		if (!result) throw std::runtime_error("base58 Bitcoin encoding failed");
		std::string output(result);
		std::free(result);
		return output;
	}

	static std::string encode_bitcoin(const std::vector<std::uint8_t>& data) {
		return encode_bitcoin(data.data(),data.size());
	}

	static std::string encode_bitcoin(const std::string& text) {
		return encode_bitcoin(text.data(),text.size());
	}

	static std::vector<std::uint8_t> decode_bitcoin(const std::string& text) {
		void* output = NULL;
		std::size_t output_size = 0;
		const int rc = base58btc_decode(text.c_str(),&output,&output_size);
		if (rc != BASE58_SUCCESS) {
			std::free(output);
			throw std::runtime_error("base58 Bitcoin decoding failed");
		}
		return detail::make_vector(output,output_size);
	}

	static std::string encode_ripple(const void* data,std::size_t size) {
		char* result = base58ripple_encode(data, size);
		if (!result) throw std::runtime_error("base58 Ripple encoding failed");
		std::string output(result);
		std::free(result);
		return output;
	}

	static std::string encode_ripple(const std::vector<std::uint8_t>& data) {
		return encode_ripple(data.data(),data.size());
	}

	static std::string encode_ripple(const std::string& text) {
		return encode_ripple(text.data(),text.size());
	}

	static std::vector<std::uint8_t> decode_ripple(const std::string& text) {
		void* output = NULL;
		std::size_t output_size = 0;
		const int rc = base58ripple_decode(text.c_str(),&output,&output_size);
		if (rc != BASE58_SUCCESS) {
			std::free(output);
			throw std::runtime_error("base58 Ripple decoding failed");
		}
		return detail::make_vector(output,output_size);
	}

	static std::string encode_flickr(const void* data,std::size_t size) {
		char* result = base58flickr_encode(data, size);
		if (!result) throw std::runtime_error("base58 Flickr encoding failed");
		std::string output(result);
		std::free(result);
		return output;
	}

	static std::string encode_flickr(const std::vector<std::uint8_t>& data) {
		return encode_flickr(data.data(),data.size());
	}

	static std::string encode_flickr(const std::string& text) {
		return encode_flickr(text.data(),text.size());
	}

	static std::vector<std::uint8_t> decode_flickr(const std::string& text) {
		void* output = NULL;
		std::size_t output_size = 0;
		const int rc = base58flickr_decode(text.c_str(),&output,&output_size);
		if (rc != BASE58_SUCCESS) {
			std::free(output);
			throw std::runtime_error("base58 Flickr decoding failed");
		}
		return detail::make_vector(output,output_size);
	}

	static std::string encode_custom(const void* data,std::size_t size,const base58_config_t& config) {
		char* result = base58_encode_custom(data,size,&config);
		if (!result) throw std::runtime_error("base58 custom encoding failed");
		std::string output(result);
		std::free(result);
		return output;
	}

	static std::string encode_custom(const std::vector<std::uint8_t>& data,const base58_config_t& config) {
		return encode_custom(data.data(),data.size(),config);
	}

	static std::string encode_custom(const std::string& text,const base58_config_t& config) {
		return encode_custom(text.data(),text.size(),config);
	}

	static std::vector<std::uint8_t> decode_custom(const std::string& text,const base58_config_t& config) {
		void* output = NULL;
		std::size_t output_size = 0;
		const int rc = base58_decode_custom(text.c_str(),&config,&output,&output_size);
		if (rc != BASE58_SUCCESS) {
			std::free(output);
			throw std::runtime_error("base58 custom decoding failed");
		}
		return detail::make_vector(output,output_size);
	}
};

// Base64
class Base64 {
public:
	static std::string encode(const void* data,std::size_t size) {
		char* result = base64_encode(data, size);
		if (!result) throw std::runtime_error("base64 encoding failed");
		std::string output(result);
		std::free(result);
		return output;
	}

	static std::string encode(const std::vector<std::uint8_t>& data){
		return encode(data.data(),data.size());
	}

	static std::string encode(const std::string& text){
		return encode(text.data(),text.size());
	}

	static std::vector<std::uint8_t> decode(const std::string& text) {
		void* output = NULL;
		std::size_t output_size = 0;
		const int rc = base64_decode(text.c_str(),&output,&output_size);
		if (rc != BASE64_SUCCESS) {
			std::free(output);
			throw std::runtime_error("base64 decoding failed");
		}
		return detail::make_vector(output,output_size);
	}

	static std::string encode_url(const void* data,std::size_t size) {
		char* result = base64url_encode(data, size);
		if (!result) throw std::runtime_error("base64 URL encoding failed");
		std::string output(result);
		std::free(result);
		return output;
	}

	static std::string encode_url(const std::vector<std::uint8_t>& data){
		return encode_url(data.data(),data.size());
	}

	static std::string encode_url(const std::string& text){
		return encode_url(text.data(),text.size());
	}

	static std::vector<std::uint8_t> decode_url(const std::string& text) {
		void* output = NULL;
		std::size_t output_size = 0;
		const int rc = base64url_decode(text.c_str(),&output,&output_size);
		if (rc != BASE64_SUCCESS) {
			std::free(output);
			throw std::runtime_error("base64 URL decoding failed");
		}
		return detail::make_vector(output,output_size);
	}

	static std::string encode_mime(const void* data,std::size_t size) {
		char* result = base64mime_encode(data, size);
		if (!result) throw std::runtime_error("base64 MIME encoding failed");
		std::string output(result);
		std::free(result);
		return output;
	}

	static std::string encode_mime(const std::vector<std::uint8_t>& data){
		return encode_mime(data.data(),data.size());
	}

	static std::string encode_mime(const std::string& text){
		return encode_mime(text.data(),text.size());
	}

	static std::vector<std::uint8_t> decode_mime(const std::string& text) {
		void* output = NULL;
		std::size_t output_size = 0;
		const int rc = base64mime_decode(text.c_str(),&output,&output_size);
		if (rc != BASE64_SUCCESS) {
			std::free(output);
			throw std::runtime_error("base64 MIME decoding failed");
		}
		return detail::make_vector(output,output_size);
	}

	static std::string encode_custom(const void* data,std::size_t size,const base64_config_t& config) {
		char* result = base64_encode_custom(data,size,&config);
		if (!result) throw std::runtime_error("base64 custom encoding failed");
		std::string output(result);
		std::free(result);
		return output;
	}

	static std::string encode_custom(const std::vector<std::uint8_t>& data,const base64_config_t& config){
		return encode_custom(data.data(),data.size(),config);
	}

	static std::string encode_custom(const std::string& text,const base64_config_t& config){
		return encode_custom(text.data(),text.size(),config);
	}

	static std::vector<std::uint8_t> decode_custom(const std::string& text,const base64_config_t& config) {
		void* output = NULL;
		std::size_t output_size = 0;
		const int rc = base64_decode_custom(text.c_str(),&config,&output,&output_size);
		if (rc != BASE64_SUCCESS) {
			std::free(output);
			throw std::runtime_error("base64 custom decoding failed");
		}
		return detail::make_vector(output,output_size);
	}
};

// AES
class Aes {
public:
	static const std::size_t block_size = AES_BLOCK_SIZE;
	Aes(const void* key,std::size_t key_size) {
		if (!key && key_size != 0) throw std::invalid_argument("AES key is null");
		if (AesInitialise(&ctx_,key,detail::checked_u32(key_size)) != 0) {
			throw std::invalid_argument("invalid AES key size");
		}
	}

	explicit Aes(const std::vector<std::uint8_t>& key) : Aes(key.data(), key.size()) { }

	Aes(const Aes&) = delete;
	Aes& operator=(const Aes&) = delete;
	Aes(Aes&&) = delete;
	Aes& operator=(Aes&&) = delete;
	~Aes() noexcept {
		detail::secure_zero(&ctx_,sizeof(ctx_));
	}

	void encrypt(const std::uint8_t input[AES_BLOCK_SIZE],std::uint8_t output[AES_BLOCK_SIZE]) const noexcept {
		AesEncrypt(&ctx_,input,output);
	}

	void decrypt(const std::uint8_t input[AES_BLOCK_SIZE],std::uint8_t output[AES_BLOCK_SIZE]) const noexcept {
		AesDecrypt(&ctx_,input,output);
	}

	void encrypt_in_place(std::uint8_t block[AES_BLOCK_SIZE]) const noexcept {
		AesEncryptInPlace(&ctx_,block);
	}

	void decrypt_in_place(std::uint8_t block[AES_BLOCK_SIZE]) const noexcept {
		AesDecryptInPlace(&ctx_,block);
	}

	static void xor_buffers(const std::uint8_t* lhs,const std::uint8_t* rhs,std::uint8_t* output,std::size_t size) {
		XorBuffers(lhs,rhs,output,detail::checked_u32(size));
	}

private:
	AesContext ctx_;
};

// AES-CBC
class AesCbc {
public:
	static const std::size_t block_size = AES_BLOCK_SIZE;
	typedef std::array<std::uint8_t,AES_BLOCK_SIZE> iv_type;

	AesCbc(const std::uint8_t* key,std::size_t key_size,const iv_type& iv) {
		if (!key && key_size != 0) throw std::invalid_argument("AES-CBC key is null");
		if (AesCbcInitialiseWithKey(&ctx_,key,detail::checked_u32(key_size),iv.data()) != 0) {
			throw std::invalid_argument("invalid AES-CBC key size or IV");
		}
	}

	AesCbc(const std::vector<std::uint8_t>& key,const iv_type& iv): AesCbc(key.data(), key.size(), iv) { }

	AesCbc(const AesCbc&) = delete;
	AesCbc& operator=(const AesCbc&) = delete;

	AesCbc(AesCbc&&) = delete;
	AesCbc& operator=(AesCbc&&) = delete;

	~AesCbc() noexcept {
		detail::secure_zero(&ctx_,sizeof(ctx_));
	}

	void encrypt(const void* input,void* output,std::size_t size) {
		validate_size(size);
		if (AesCbcEncrypt(&ctx_,input,output,detail::checked_u32(size)) != 0) {
			throw std::runtime_error("AES-CBC encryption failed");
		}
	}

	void decrypt(const void* input,void* output,std::size_t size) {
		validate_size(size);
		if (AesCbcDecrypt(&ctx_,input,output,detail::checked_u32(size)) != 0) {
			throw std::runtime_error("AES-CBC decryption failed");
		}
	}

	static std::vector<std::uint8_t> encrypt_data(const std::vector<std::uint8_t>& key,const iv_type& iv,const std::vector<std::uint8_t>& data) {
		validate_size(data.size());
		std::vector<std::uint8_t> output(data.size());
		if (AesCbcEncryptWithKey(
			key.data(),detail::checked_u32(key.size()),iv.data(),
			data.data(),output.data(),detail::checked_u32(data.size())) != 0) {
			throw std::runtime_error("AES-CBC encryption failed");
		}
		return output;
	}

	static std::vector<std::uint8_t> decrypt_data(const std::vector<std::uint8_t>& key,const iv_type& iv,const std::vector<std::uint8_t>& data) {
		validate_size(data.size());
		std::vector<std::uint8_t> output(data.size());

		if (AesCbcDecryptWithKey(
			key.data(),detail::checked_u32(key.size()),iv.data(),
			data.data(),output.data(),detail::checked_u32(data.size())) != 0) {
			throw std::runtime_error("AES-CBC decryption failed");
		}
		return output;
	}

private:
	static void validate_size(std::size_t size) {
		if (size % block_size != 0) throw std::invalid_argument("AES-CBC data size must be a multiple of 16 bytes");
	}
	AesCbcContext ctx_;
};

// AES-CTR
class AesCtr {
public:
	static const std::size_t iv_size = AES_CTR_IV_SIZE;
	typedef std::array<std::uint8_t,AES_CTR_IV_SIZE> iv_type;

	AesCtr(const std::uint8_t* key,std::size_t key_size,const iv_type& iv) {
		if (!key && key_size != 0) throw std::invalid_argument("AES-CTR key is null");
		if (AesCtrInitialiseWithKey(&ctx_,key,detail::checked_u32(key_size),iv.data()) != 0) {
			throw std::invalid_argument("invalid AES-CTR key size or IV");
		}
	}

	AesCtr(const std::vector<std::uint8_t>& key,const iv_type& iv) : AesCtr(key.data(), key.size(), iv) { }

	AesCtr(const AesCtr&) = delete;
	AesCtr& operator=(const AesCtr&) = delete;

	AesCtr(AesCtr&&) = delete;
	AesCtr& operator=(AesCtr&&) = delete;

	~AesCtr() noexcept {
		detail::secure_zero(&ctx_,sizeof(ctx_));
	}

	void seek(std::uint64_t index) noexcept {
		AesCtrSetStreamIndex(&ctx_,index);
	}

	void xor_stream(const void* input,void* output,std::size_t size) {
		AesCtrXor(&ctx_,input,output,detail::checked_u32(size));
	}

	void keystream(void* output,std::size_t size) {
		AesCtrOutput(&ctx_,output,detail::checked_u32(size));
	}

	static std::vector<std::uint8_t> xor_data(
		const std::vector<std::uint8_t>& key,
		const iv_type& iv,
		const std::vector<std::uint8_t>& data
	) {
		std::vector<std::uint8_t> output(data.size());
		if (AesCtrXorWithKey(
				key.data(),detail::checked_u32(key.size()),iv.data(),data.data(),
				output.data(),detail::checked_u32(data.size())) != 0) {
			throw std::runtime_error("AES-CTR operation failed");
		}
		return output;
	}

private:
	AesCtrContext ctx_;
};

// AES-OFB
class AesOfb {
public:
	static const std::size_t block_size = AES_BLOCK_SIZE;
	typedef std::array<std::uint8_t,AES_BLOCK_SIZE> iv_type;

	AesOfb(const std::uint8_t* key,std::size_t key_size,const iv_type& iv) {
		if (!key && key_size != 0) throw std::invalid_argument("AES-OFB key is null");
		if (AesOfbInitialiseWithKey(&ctx_,key,detail::checked_u32(key_size),iv.data()) != 0) {
			throw std::invalid_argument("invalid AES-OFB key size or IV");
		}
	}

	AesOfb(const std::vector<std::uint8_t>& key,const iv_type& iv) : AesOfb(key.data(), key.size(), iv) { }

	AesOfb(const AesOfb&) = delete;
	AesOfb& operator=(const AesOfb&) = delete;

	AesOfb(AesOfb&&) = delete;
	AesOfb& operator=(AesOfb&&) = delete;

	~AesOfb() noexcept {
		detail::secure_zero(&ctx_,sizeof(ctx_));
	}

	void xor_stream(const void* input,void* output,std::size_t size) {
		AesOfbXor(&ctx_,input,output,detail::checked_u32(size));
	}

	void keystream(void* output,std::size_t size) {
		AesOfbOutput(&ctx_,output,detail::checked_u32(size));
	}

	static std::vector<std::uint8_t> xor_data(const std::vector<std::uint8_t>& key,const iv_type& iv,const std::vector<std::uint8_t>& data) {
		std::vector<std::uint8_t> output(data.size());
		if (AesOfbXorWithKey(
			key.data(),detail::checked_u32(key.size()),iv.data(),
			data.data(),output.data(),detail::checked_u32(data.size())) != 0) {
			throw std::runtime_error("AES-OFB operation failed");
		}
		return output;
	}

private:
	AesOfbContext ctx_;
};

// CRC8
class Crc8 {
public:
	enum class Variant {
		SMBUS,
		AUTOSAR,
		MAXIM,
		ROHC,
		WCDMA,
		SAE_J1850,
		MIFARE_MAD
	};

	explicit Crc8(Variant variant = Variant::SMBUS,bool reflected = false)
	: reflected_(reflected), init_(get_init(variant)), xorout_(get_xorout(variant)) {
		const std::uint8_t polynomial = get_polynomial(variant, reflected_);
		if (reflected_) {
			crc8_reflected_table(table_.data(),polynomial);
		} else {
			crc8_init_table(table_.data(),polynomial);
		}
	}

	std::uint8_t compute(const void* data,std::size_t size) const {
		std::uint8_t crc = ccrc8(init_,data,size,table_.data());
		return (std::uint8_t)(crc ^ xorout_);
	}

	std::uint8_t compute(const std::vector<std::uint8_t>& data) const {
		return compute(data.data(), data.size());
	}

	std::uint8_t compute(const std::string& text) const {
		return compute(text.data(), text.size());
	}

private:
	std::array<std::uint8_t, 256> table_;
	bool reflected_;
	std::uint8_t init_;
	std::uint8_t xorout_;

	static std::uint8_t get_polynomial(Variant variant,bool reflected) {
		switch (variant) {
			case Variant::SMBUS: return reflected ? CRC8_SMBUS_POLY_REFLECTED : CRC8_SMBUS_POLY;
			case Variant::AUTOSAR: return reflected ? CRC8_AUTOSAR_POLY_REFLECTED : CRC8_AUTOSAR_POLY;
			case Variant::MAXIM: return reflected ? CRC8_MAXIM_POLY_REFLECTED : CRC8_MAXIM_POLY;
			case Variant::ROHC: return reflected ? CRC8_ROHC_POLY_REFLECTED : CRC8_ROHC_POLY;
			case Variant::WCDMA: return reflected ? CRC8_WCDMA_POLY_REFLECTED : CRC8_WCDMA_POLY;
			case Variant::SAE_J1850: return reflected ? CRC8_SAE_J1850_POLY_REFLECTED : CRC8_SAE_J1850_POLY;
			case Variant::MIFARE_MAD: return reflected ? CRC8_MIFARE_MAD_POLY_REFLECTED : CRC8_MIFARE_MAD_POLY;
		}

		throw std::invalid_argument("unknown CRC8 variant");
	}

	static std::uint8_t get_init(Variant variant) {
		switch (variant) {
			case Variant::SMBUS: return CRC8_INIT_0;
			case Variant::AUTOSAR: return CRC8_INIT_FF;
			case Variant::MAXIM: return CRC8_INIT_0;
			case Variant::ROHC: return CRC8_INIT_FF;
			case Variant::WCDMA: return CRC8_INIT_0;
			case Variant::SAE_J1850: return CRC8_INIT_FF;
			case Variant::MIFARE_MAD: return CRC8_INIT_C7;
		}
		throw std::invalid_argument("unknown CRC8 variant");
	}

	static std::uint8_t get_xorout(Variant variant) {
		switch (variant) {
			case Variant::SMBUS: return CRC8_XOR_0;
			case Variant::AUTOSAR: return CRC8_XOR_FF;
			case Variant::MAXIM: return CRC8_XOR_0;
			case Variant::ROHC: return CRC8_XOR_0;
			case Variant::WCDMA: return CRC8_XOR_0;
			case Variant::SAE_J1850: return CRC8_XOR_FF;
			case Variant::MIFARE_MAD: return CRC8_XOR_0;
		}

		throw std::invalid_argument("unknown CRC8 variant");
	}
};

// CRC8 extended
class Crc8Ext {
public:
	enum class Variant {
		SMBUS,
		AUTOSAR,
		MAXIM,
		ROHC,
		WCDMA,
		SAE_J1850,
		MIFARE_MAD
	};

	static std::uint8_t compute(
		const void* data,
		std::size_t size,
		Variant variant = Variant::SMBUS
	) {
		switch (variant) {
			case Variant::SMBUS:
				return crc8_smbus(data,size);

			case Variant::AUTOSAR:
				return crc8_autosar(data,size);

			case Variant::MAXIM:
				return crc8_maxim(data,size);

			case Variant::ROHC:
				return crc8_rohc(data,size);

			case Variant::WCDMA:
				return crc8_wcdma(data,size);

			case Variant::SAE_J1850:
				return crc8_sae_j1850(data,size);

			case Variant::MIFARE_MAD:
				return crc8_mifare_mad(data,size);
		}

		throw std::invalid_argument("unknown CRC8 variant");
	}

	static std::uint8_t compute(
		const std::vector<std::uint8_t>& data,
		Variant variant = Variant::SMBUS
	) {
		return compute(data.data(),data.size(),variant);
	}

	static std::uint8_t compute(
		const std::string& text,
		Variant variant = Variant::SMBUS
	) {
		return compute(text.data(),text.size(),variant);
	}

#ifdef LIBHASH_USE_FILE
	static std::uint8_t compute_file(
		const std::string& path,
		Variant variant = Variant::SMBUS
	) {
		switch (variant) {
			case Variant::SMBUS:
				return crc8_smbus_file(path.c_str());

			case Variant::AUTOSAR:
				return crc8_autosar_file(path.c_str());

			case Variant::MAXIM:
				return crc8_maxim_file(path.c_str());

			case Variant::ROHC:
				return crc8_rohc_file(path.c_str());

			case Variant::WCDMA:
				return crc8_wcdma_file(path.c_str());

			case Variant::SAE_J1850:
				return crc8_sae_j1850_file(path.c_str());

			case Variant::MIFARE_MAD:
				return crc8_mifare_mad_file(path.c_str());
		}

		throw std::invalid_argument("unknown CRC8 variant");
	}

#ifdef LIBHASH_USE_FD
	static std::uint8_t compute_fd(
		int fd,
		Variant variant = Variant::SMBUS
	) {
		switch (variant) {
			case Variant::SMBUS:
				return crc8_fd(fd);

			case Variant::AUTOSAR:
				return crc8_autosar_fd(fd);

			case Variant::MAXIM:
				return crc8_maxim_fd(fd);

			case Variant::ROHC:
				return crc8_rohc_fd(fd);

			case Variant::WCDMA:
				return crc8_wcdma_fd(fd);

			case Variant::SAE_J1850:
				return crc8_sae_j1850_fd(fd);

			case Variant::MIFARE_MAD:
				return crc8_mifare_mad_fd(fd);
		}

		throw std::invalid_argument("unknown CRC8 variant");
	}
#else
	static std::uint8_t compute_fp(
		FILE* fp,
		Variant variant = Variant::SMBUS
	) {
		switch (variant) {
			case Variant::SMBUS:
				return crc8_fp(fp);

			case Variant::AUTOSAR:
				return crc8_autosar_fp(fp);

			case Variant::MAXIM:
				return crc8_maxim_fp(fp);

			case Variant::ROHC:
				return crc8_rohc_fp(fp);

			case Variant::WCDMA:
				return crc8_wcdma_fp(fp);

			case Variant::SAE_J1850:
				return crc8_sae_j1850_fp(fp);

			case Variant::MIFARE_MAD:
				return crc8_mifare_mad_fp(fp);
		}

		throw std::invalid_argument("unknown CRC8 variant");
	}
#endif
#endif
};

// CRC16
class Crc16 {
public:
	enum class Variant {
		IBM,
		CCITT,
		XMODEM,
		MODBUS,
		KERMIT,
		DNP,
		USB
	};

	explicit Crc16(Variant variant = Variant::IBM,bool reflected = true)
	: reflected_(reflected),init_(get_init(variant)), xorout_(get_xorout(variant)) {
		const std::uint16_t polynomial = get_polynomial(variant,reflected_);
		if (reflected_) {
			crc16_reflected_table(table_.data(),polynomial);
		} else {
			crc16_init_table(table_.data(),polynomial);
		}
	}

	std::uint16_t compute(const void* data,std::size_t size) const {
		std::uint16_t crc;
		if (reflected_) {
			crc = ccrc16_reflected(init_,data,size,table_.data());
		} else {
			crc = ccrc16(init_,data,size,table_.data());
		}
		return static_cast<std::uint16_t>(crc ^ xorout_);
	}

	std::uint16_t compute(const std::vector<std::uint8_t>& data) const {
		return compute(data.data(),data.size());
	}

	std::uint16_t compute(const std::string& text) const {
		return compute(text.data(),text.size());
	}

private:
	std::array<std::uint16_t,256> table_;
	bool reflected_;
	std::uint16_t init_;
	std::uint16_t xorout_;

	static std::uint16_t get_polynomial(Variant variant,bool reflected) {
		switch (variant) {
			case Variant::IBM: return reflected ? CRC16_IBM_POLY_REFLECTED : CRC16_IBM_POLY;
			case Variant::CCITT: return reflected ? CRC16_CCITT_POLY_REFLECTED : CRC16_CCITT_POLY;
			case Variant::XMODEM: return reflected ? CRC16_XMODEM_POLY_REFLECTED : CRC16_XMODEM_POLY;
			case Variant::MODBUS: return reflected ? CRC16_MODBUS_POLY_REFLECTED : CRC16_MODBUS_POLY;
			case Variant::KERMIT: return reflected ? CRC16_KERMIT_POLY_REFLECTED : CRC16_KERMIT_POLY;
			case Variant::DNP: return reflected ? CRC16_DNP_POLY_REFLECTED : CRC16_DNP_POLY;
			case Variant::USB: return reflected ? CRC16_USB_POLY_REFLECTED : CRC16_USB_POLY;
		}
		throw std::invalid_argument("unknown CRC16 variant");
	}

	static std::uint16_t get_init(Variant variant) {
		switch (variant) {
			case Variant::IBM: return CRC16_INIT_0;
			case Variant::CCITT: return CRC16_INIT_FF;
			case Variant::XMODEM: return CRC16_INIT_0;
			case Variant::MODBUS: return CRC16_INIT_FF;
			case Variant::KERMIT: return CRC16_INIT_0;
			case Variant::DNP: return CRC16_INIT_0;
			case Variant::USB: return CRC16_INIT_FF;
		}
		throw std::invalid_argument("unknown CRC16 variant");
	}

	static std::uint16_t get_xorout(Variant variant) {
		switch (variant) {
			case Variant::IBM: return CRC16_XOR_0;
			case Variant::CCITT: return CRC16_XOR_0;
			case Variant::XMODEM: return CRC16_XOR_0;
			case Variant::MODBUS: return CRC16_XOR_0;
			case Variant::KERMIT: return CRC16_XOR_0;
			case Variant::DNP: return CRC16_XOR_FF;
			case Variant::USB: return CRC16_XOR_FF;
		}
		throw std::invalid_argument("unknown CRC16 variant");
	}
};

// CRC16 extended
class Crc16Ext {
public:
	enum class Variant {
		IBM,
		MODBUS,
		USB,
		CCITT,
		XMODEM,
		KERMIT,
		DNP
	};

	static std::uint16_t compute(const void* data,std::size_t size,Variant variant = Variant::IBM) {
		switch (variant) {
			case Variant::IBM: return crc16_ibm(data,size);
			case Variant::MODBUS: return crc16_modbus(data,size);
			case Variant::USB: return crc16_usb(data,size);
			case Variant::CCITT: return crc16_ccitt(data,size);
			case Variant::XMODEM: return crc16_xmodem(data,size);
			case Variant::KERMIT: return crc16_kermit(data,size);
			case Variant::DNP: return crc16_dnp(data,size);
		}
		throw std::invalid_argument("unknown CRC16 variant");
	}

	static std::uint16_t compute(const std::vector<std::uint8_t>& data,Variant variant = Variant::IBM) {
		return compute(data.data(),data.size(),variant);
	}

	static std::uint16_t compute(const std::string& text,Variant variant = Variant::IBM) {
		return compute(text.data(),text.size(),variant);
	}
#ifdef LIBHASH_USE_FILE
	static std::uint16_t compute_file(const std::string& path,Variant variant = Variant::IBM) {
		switch (variant) {
			case Variant::IBM: return crc16_ibm_file(path.c_str());
			case Variant::MODBUS: return crc16_modbus_file(path.c_str());
			case Variant::USB: return crc16_usb_file(path.c_str());
			case Variant::CCITT: return crc16_ccitt_file(path.c_str());
			case Variant::XMODEM: return crc16_xmodem_file(path.c_str());
			case Variant::KERMIT: return crc16_kermit_file(path.c_str());
			case Variant::DNP: return crc16_dnp_file(path.c_str());
		}
		throw std::invalid_argument("unknown CRC16 variant");
	}
#ifdef LIBHASH_USE_FD
	static std::uint16_t compute_fd(int fd,Variant variant = Variant::IBM) {
		switch (variant) {
			case Variant::IBM: return crc16_ibm_fd(fd);
			case Variant::MODBUS: return crc16_modbus_fd(fd);
			case Variant::USB: return crc16_usb_fd(fd);
			case Variant::CCITT: return crc16_ccitt_fd(fd);
			case Variant::XMODEM: return crc16_xmodem_fd(fd);
			case Variant::KERMIT: return crc16_kermit_fd(fd);
			case Variant::DNP: return crc16_dnp_fd(fd);
		}
		throw std::invalid_argument("unknown CRC16 variant");
	}
#else
	static std::uint16_t compute_fp(FILE* fp,Variant variant = Variant::IBM) {
		switch (variant) {
			case Variant::IBM: return crc16_ibm_fp(fp);
			case Variant::MODBUS: return crc16_modbus_fp(fp);
			case Variant::USB: return crc16_usb_fp(fp);
			case Variant::CCITT: return crc16_ccitt_fp(fp);
			case Variant::XMODEM: return crc16_xmodem_fp(fp);
			case Variant::KERMIT: return crc16_kermit_fp(fp);
			case Variant::DNP: return crc16_dnp_fp(fp);
		}
		throw std::invalid_argument("unknown CRC16 variant");
	}
#endif /* LIBHASH_USE_FD */
#endif /* LIBHASH_USE_FILE */
};

// CRC32
class Crc32 {
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

	explicit Crc32(Variant variant = Variant::IEEE,bool reflected = true) : reflected_(reflected) {
		const std::uint32_t polynomial = get_polynomial(variant,reflected_);
		if (reflected_) {
			crc32_reflected_table(table_.data(),polynomial);
		} else {
			crc32_init_table(table_.data(),polynomial);
		}
	}

	std::uint32_t compute(const void* data,std::size_t size,std::uint32_t initial = 0xFFFFFFFFu) const {
		std::uint32_t crc;
		if (reflected_) {
			crc = ccrc32_reflected(initial,data,size,table_.data());
		} else {
			crc = ccrc32(initial,data,size,table_.data());
		}
		return crc ^ initial;
	}

	std::uint32_t compute(const std::vector<std::uint8_t>& data,std::uint32_t initial = 0xFFFFFFFFu) const {
		return compute(data.data(),data.size(),initial);
	}

	std::uint32_t compute(const std::string& text,std::uint32_t initial = 0xFFFFFFFFu) const {
		return compute(text.data(),text.size(),initial);
	}

private:
	std::array<std::uint32_t, 256> table_;
	bool reflected_;
	static std::uint32_t get_polynomial(Variant variant,bool reflected) {
		switch (variant) {
			case Variant::IEEE: return reflected ? CRC32_POLY_REFLECTED : CRC32_POLY;
			case Variant::CRC32C: return reflected ? CRC32C_POLY_REFLECTED : CRC32C_POLY;
			case Variant::CRC32K: return reflected ? CRC32K_POLY_REFLECTED : CRC32K_POLY;
			case Variant::CRC32Q: return reflected ? CRC32Q_POLY_REFLECTED : CRC32Q_POLY;
			case Variant::CRC32D: return reflected ? CRC32D_POLY_REFLECTED : CRC32D_POLY;
			case Variant::XFER: return reflected ? CRC32_XFER_POLY_REFLECTED : CRC32_XFER_POLY;
			case Variant::AUTOSAR: return reflected ? CRC32_AUTOSAR_POLY_REFLECTED : CRC32_AUTOSAR_POLY;
		}
		throw std::invalid_argument("unknown CRC32 variant");
	}
};

// CRC32 extended
class Crc32Ext{
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

	static std::uint32_t compute(const void* data,std::size_t size,Variant variant = Variant::IEEE) {
		switch (variant) {
			case Variant::IEEE: return crc32_ieee(data, size);
			case Variant::CRC32C: return crc32c(data, size);
			case Variant::CRC32K: return crc32k(data, size);
			case Variant::CRC32Q: return crc32q(data, size);
			case Variant::CRC32D: return crc32d(data, size);
			case Variant::XFER: return crc32_xfer(data, size);
			case Variant::AUTOSAR: return crc32_autosar(data, size);
		}
		throw std::invalid_argument("unknown CRC32 variant");
	}

	static std::uint32_t compute(const std::vector<std::uint8_t>& data,Variant variant = Variant::IEEE) {
		return compute(data.data(),data.size(),variant);
	}

	static std::uint32_t compute(const std::string& text,Variant variant = Variant::IEEE) {
		return compute(text.data(),text.size(),variant);
	}

#ifdef LIBHASH_USE_FILE
	static std::uint32_t compute_file(const std::string& path,Variant variant = Variant::IEEE) {
		switch (variant) {
			case Variant::IEEE:
				return crc32_ieee_file(path.c_str());
			case Variant::CRC32C:
				return crc32c_file(path.c_str());
			case Variant::CRC32K:
				return crc32k_file(path.c_str());
			case Variant::CRC32Q:
				return crc32q_file(path.c_str());
			case Variant::CRC32D:
				return crc32d_file(path.c_str());
			case Variant::XFER:
				return crc32_xfer_file(path.c_str());
			case Variant::AUTOSAR:
				return crc32_autosar_file(path.c_str());
		}
		throw std::invalid_argument("unknown CRC32 variant");
	}

#ifdef LIBHASH_USE_FD
	static std::uint32_t compute_fd(int fd,Variant variant = Variant::IEEE) {
		switch (variant) {
			case Variant::IEEE:
				return crc32_ieee_fd(fp);
			case Variant::CRC32C:
				return crc32c_fd(fd);
			case Variant::CRC32K:
				return crc32k_fd(fd);
			case Variant::CRC32Q:
				return crc32q_fd(fd);
			case Variant::CRC32D:
				return crc32d_fd(fd);
			case Variant::XFER:
				return crc32_xfer_fd(fd);
			case Variant::AUTOSAR:
				return crc32_autosar_fd(fd);
		}
		throw std::invalid_argument("unknown CRC32 variant");
	}
#else
	static std::uint32_t compute_fp(FILE* fp,Variant variant = Variant::IEEE) {
		switch (variant) {
			case Variant::IEEE:
				return crc32_ieee_fp(fp);
			case Variant::CRC32C:
				return crc32c_fp(fp);
			case Variant::CRC32K:
				return crc32k_fp(fp);
			case Variant::CRC32Q:
				return crc32q_fp(fp);
			case Variant::CRC32D:
				return crc32d_fp(fp);
			case Variant::XFER:
				return crc32_xfer_fp(fp);
			case Variant::AUTOSAR:
				return crc32_autosar_fp(fp);
		}
		throw std::invalid_argument("unknown CRC32 variant");
	}
#endif
#endif
};

// CRC64
class Crc64 {
public:
	enum class Variant {
		ECMA,
		WE,
		XZ,
		ISO
	};

	explicit Crc64(Variant variant = Variant::ECMA,bool reflected = true) : variant_(variant),reflected_(reflected) {
		const std::uint64_t polynomial = get_polynomial(variant_,reflected_);
		if (reflected_) {
			crc64_reflected_table(table_.data(),polynomial);
		} else {
			crc64_init_table(table_.data(),polynomial);
		}
	}

	std::uint64_t compute(const void* data,std::size_t size) const {
		const Parameters p = get_parameters(variant_,reflected_);
		std::uint64_t crc;
		if (reflected_) {
			crc = ccrc64_reflected(p.init,data,size,table_.data());
		} else {
			crc = ccrc64(p.init,data,size,table_.data());
		}
		return crc ^ p.xorout;
	}

	std::uint64_t compute(const std::vector<std::uint8_t>& data) const {
		return compute(data.data(),data.size());
	}

	std::uint64_t compute(const std::string& text) const {
		return compute(text.data(),text.size());
	}

private:
	struct Parameters {
		std::uint64_t init;
		std::uint64_t xorout;
	};

	std::array<std::uint64_t,256> table_;
	Variant variant_;
	bool reflected_;

	static std::uint64_t get_polynomial(Variant variant,bool reflected) {
		switch (variant) {
			case Variant::ECMA: return reflected ? CRC64_ECMA_POLY_REFLECTED : CRC64_ECMA_POLY;
			case Variant::WE: return reflected ? CRC64_WE_POLY_REFLECTED : CRC64_WE_POLY;
			case Variant::XZ: return reflected ? CRC64_XZ_POLY_REFLECTED : CRC64_XZ_POLY;
			case Variant::ISO: return reflected ? CRC64_ISO_POLY_REFLECTED : CRC64_ISO_POLY;
		}

		throw std::invalid_argument("unknown CRC64 variant");
	}

	static Parameters get_parameters(Variant variant,bool reflected) {
		(void)reflected;
		switch (variant) {
			case Variant::ECMA: return {CRC64_INIT_0,CRC64_XOR_0};
			case Variant::WE: return {CRC64_INIT_0,CRC64_XOR_FF};
			case Variant::XZ: return {CRC64_INIT_FF,CRC64_XOR_FF};
			case Variant::ISO: return {CRC64_INIT_0,CRC64_XOR_0};
		}
		throw std::invalid_argument("unknown CRC64 variant");
	}
};

// CRC64 extended
class Crc64Ext {
public:
	enum class Variant {
		ECMA,
		WE,
		XZ,
		ISO
	};

	static std::uint64_t compute(const void* data,std::size_t size,Variant variant = Variant::ECMA) {
		switch (variant) {
			case Variant::ECMA: return crc64_ecma(data,size);
			case Variant::WE: return crc64_we(data,size);
			case Variant::XZ: return crc64_xz(data,size);
			case Variant::ISO: return crc64_iso(data,size);
		}
		throw std::invalid_argument("unknown CRC64 variant");
	}

	static std::uint64_t compute(const std::vector<std::uint8_t>& data,Variant variant = Variant::ECMA) {
		return compute(data.data(),data.size(),variant);
	}

	static std::uint64_t compute(const std::string& text,Variant variant = Variant::ECMA) {
		return compute(text.data(),text.size(),variant);
	}

#ifdef LIBHASH_USE_FILE
	static std::uint64_t compute_file(const std::string& path,Variant variant = Variant::ECMA) {
		switch (variant) {
			case Variant::ECMA:
				return crc64_ecma_file(path.c_str());
			case Variant::WE:
				return crc64_we_file(path.c_str());
			case Variant::XZ:
				return crc64_xz_file(path.c_str());
			case Variant::ISO:
				return crc64_iso_file(path.c_str());
		}
		throw std::invalid_argument("unknown CRC64 variant");
	}

#ifdef LIBHASH_USE_FD
	static std::uint64_t compute_fd(int fd,Variant variant = Variant::ECMA) {
		switch (variant) {
			case Variant::ECMA:
				return crc64_ecma_fd(fd);
			case Variant::WE:
				return crc64_we_fd(fd);
			case Variant::XZ:
				return crc64_xz_fd(fd);
			case Variant::ISO:
				return crc64_iso_fd(fd);
		}
		throw std::invalid_argument("unknown CRC64 variant");
	}
#else
	static std::uint64_t compute_fp(FILE* fp,Variant variant = Variant::ECMA) {
		switch (variant) {
			case Variant::ECMA:
				return crc64_ecma_fp(fp);
			case Variant::WE:
				return crc64_we_fp(fp);
			case Variant::XZ:
				return crc64_xz_fp(fp);
			case Variant::ISO:
				return crc64_iso_fp(fp);
		}
		throw std::invalid_argument("unknown CRC64 variant");
	}
#endif
#endif
};

// RC4
class Rc4 {
public:
	Rc4(const void* key,std::size_t key_size,std::uint32_t drop = 0) {
		if (!key && key_size != 0) throw std::invalid_argument("RC4 key is null");
		Rc4Initialise(&ctx_,key,detail::checked_u32(key_size),drop);
	}

	explicit Rc4(const std::vector<std::uint8_t>& key,std::uint32_t drop = 0) : Rc4(key.data(),key.size(),drop) { }

	Rc4(const Rc4&) = delete;
	Rc4& operator=(const Rc4&) = delete;

	Rc4(Rc4&&) = delete;
	Rc4& operator=(Rc4&&) = delete;

	~Rc4() noexcept {
		detail::secure_zero(&ctx_,sizeof(ctx_));
	}

	void generate(void* output,std::size_t size) {
		if (!output && size != 0) throw std::invalid_argument("RC4 output buffer is null");
		Rc4Output(&ctx_,output,detail::checked_u32(size));
	}

	void xor_stream(const void* input,void* output,std::size_t size) {
		if (size != 0) {
			if (!input) throw std::invalid_argument("RC4 input buffer is null");
			if (!output) throw std::invalid_argument("RC4 output buffer is null");
		}
		Rc4Xor(&ctx_,input,output,detail::checked_u32(size));
	}

private:
	Rc4Context ctx_;
};

} // namespace hash

#endif // HASH_HPP
