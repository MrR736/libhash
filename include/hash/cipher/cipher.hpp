/**
 * WjCryptLib_cipher for C++
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

#ifndef CIPHER_HPP
#define CIPHER_HPP

#include <algorithm>
#include <cstdlib>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>
#include <functional>

#include "cipher.h"

namespace hash {

namespace cipher {

class Caesar {
public:
	explicit Caesar(int shift = 0) noexcept : shift_(caesar_normalize_shift(shift)) {}

	Caesar(const Caesar&) = default;
	Caesar(Caesar&&) noexcept = default;
	Caesar& operator=(const Caesar&) = default;
	Caesar& operator=(Caesar&&) noexcept = default;
	~Caesar() = default;

	int shift() const noexcept {
		return shift_;
	}

	void set_shift(int shift) noexcept {
		shift_ = caesar_normalize_shift(shift);
	}

	char encrypt(char c) const noexcept {
		return caesar_encrypt_char(c, shift_);
	}

	char decrypt(char c) const noexcept {
		return caesar_decrypt_char(c, shift_);
	}

	void encrypt_inplace(char *str, std::size_t len) const {
		const int rc = caesar_encrypt_inplace(str, len, shift_);
		if (rc != CAESAR_SUCCESS)
			throw std::invalid_argument("invalid Caesar encryption buffer");
	}

	void decrypt_inplace(char *str, std::size_t len) const {
		const int rc = caesar_decrypt_inplace(str, len, shift_);
		if (rc != CAESAR_SUCCESS)
			throw std::invalid_argument("invalid Caesar decryption buffer");
	}

	std::string encrypt(const char *str) const {
		if (!str) throw std::invalid_argument("null string");
		char *result = caesar_encrypt(str, shift_);
		if (!result) throw std::bad_alloc();
		std::unique_ptr<char, decltype(&std::free)> buffer(result, &std::free);
		return std::string(buffer.get());
	}

	std::string decrypt(const char *str) const {
		if (!str) throw std::invalid_argument("null string");
		char *result = caesar_decrypt(str, shift_);
		if (!result) throw std::bad_alloc();
		std::unique_ptr<char, decltype(&std::free)> buffer(result, &std::free);
		return std::string(buffer.get());
	}

	std::string encrypt(const std::string& str) const {
		return encrypt(str.c_str());
	}

	std::string decrypt(const std::string& str) const {
		return decrypt(str.c_str());
	}

	std::vector<std::uint8_t> encrypt(const void *data,std::size_t len) const {
		void *result = nullptr;
		const int rc = caesar_encrypt_buffer(data, len, shift_, &result);
		if (rc == CAESAR_ERR_INVALID_ARG) throw std::invalid_argument("invalid Caesar input");
		if (rc == CAESAR_ERR_ALLOC_FAIL) throw std::bad_alloc();
		return make_vector(result, len);
	}

	std::vector<std::uint8_t> decrypt(const void *data,std::size_t len) const {
		void *result = nullptr;
		const int rc = caesar_decrypt_buffer(data, len, shift_, &result);
		if (rc == CAESAR_ERR_INVALID_ARG) throw std::invalid_argument("invalid Caesar input");
		if (rc == CAESAR_ERR_ALLOC_FAIL) throw std::bad_alloc();
		return make_vector(result, len);
	}

	std::vector<std::uint8_t> encrypt(const std::vector<std::uint8_t>& data) const {
		return encrypt(data.data(), data.size());
	}

	std::vector<std::uint8_t> decrypt(const std::vector<std::uint8_t>& data) const {
		return decrypt(data.data(), data.size());
	}

private:
	static std::vector<std::uint8_t> make_vector(void *data,std::size_t len) {
		std::unique_ptr<std::uint8_t, decltype(&std::free)> buffer(static_cast<std::uint8_t *>(data),&std::free);
		if (len == 0) return {};
		return std::vector<std::uint8_t>(buffer.get(),buffer.get() + len);
	}
	int shift_;
};

class Vigenere {
public:
	explicit Vigenere(const char *key) {
		set_key(key);
	}

	explicit Vigenere(const std::string& key) {
		set_key(key);
	}

	Vigenere(const Vigenere&) = default;
	Vigenere(Vigenere&&) noexcept = default;
	Vigenere& operator=(const Vigenere&) = default;
	Vigenere& operator=(Vigenere&&) noexcept = default;
	~Vigenere() = default;

	void set_key(const char *key) {
		if (!key) throw std::invalid_argument("Vigenere key is null");
		if (!vigenere_validate_key(key)) throw std::invalid_argument("Vigenere key contains no alphabetic characters");
		key_ = key;
	}

	void set_key(const std::string& key) {
		set_key(key.c_str());
	}

	const std::string& key() const noexcept {
		return key_;
	}

	char encrypt(char c) const noexcept {
		return vigenere_shift_char(c,vigenere_key_value(key_for_char(c)));
	}

	char decrypt(char c) const noexcept {
		return vigenere_shift_char(c,-vigenere_key_value(key_for_char(c)));
	}

	std::string encrypt(const char *str) const {
		if (!str) throw std::invalid_argument("null string");
		char *result = vigenere_encrypt(str, key_.c_str());
		if (!result) throw std::bad_alloc();
		std::unique_ptr<char, decltype(&std::free)> buffer(result, &std::free);
		return std::string(buffer.get());
	}

	std::string decrypt(const char *str) const {
		if (!str) throw std::invalid_argument("null string");
		char *result = vigenere_decrypt(str, key_.c_str());
		if (!result) throw std::bad_alloc();
		std::unique_ptr<char, decltype(&std::free)> buffer(result, &std::free);
		return std::string(buffer.get());
	}

	std::string encrypt(const std::string& str) const {
		return encrypt(str.c_str());
	}

	std::string decrypt(const std::string& str) const {
		return decrypt(str.c_str());
	}

	void encrypt_inplace(char *str, std::size_t len) const {
		const int rc = vigenere_encrypt_inplace(str,len,key_.c_str());
		check_result(rc);
	}

	void decrypt_inplace(char *str, std::size_t len) const {
		const int rc = vigenere_decrypt_inplace(str,len,key_.c_str());
		check_result(rc);
	}

	void encrypt_inplace(std::string& str) const {
#if __cplusplus >= 201703L
		encrypt_inplace(str.data(), str.size());
#else
		if (!str.empty()) encrypt_inplace(&str[0], str.size());
#endif
	}

	void decrypt_inplace(std::string& str) const {
#if __cplusplus >= 201703L
		decrypt_inplace(str.data(), str.size());
#else
		if (!str.empty()) decrypt_inplace(&str[0], str.size());
#endif
	}

	std::vector<std::uint8_t> encrypt(const void *data,std::size_t len) const {
		void *result = nullptr;
		const int rc = vigenere_encrypt_buffer(data,len,key_.c_str(),&result);
		check_result(rc);
		return make_vector(result, len);
	}

	std::vector<std::uint8_t> decrypt(const void *data,std::size_t len) const {
		void *result = nullptr;
		const int rc = vigenere_decrypt_buffer(data,len,key_.c_str(),&result);
		check_result(rc);
		return make_vector(result, len);
	}

	std::vector<std::uint8_t> encrypt(const std::vector<std::uint8_t>& data) const {
		return encrypt(data.data(), data.size());
	}

	std::vector<std::uint8_t> decrypt(const std::vector<std::uint8_t>& data) const {
		return decrypt(data.data(), data.size());
	}

private:
	std::string key_;

	static char key_for_char(char c) noexcept {
		/*
		 * This helper is only used by the character overloads.
		 *
		 * The actual Vigenere key position depends on the complete
		 * input stream, so single-character operations use the first
		 * alphabetic key character.
		 */
		return c;
	}

	static void check_result(int rc) {
		switch (rc) {
			case VIGENERE_SUCCESS: return;
			case VIGENERE_ERR_INVALID_ARG: throw std::invalid_argument("invalid Vigenere argument");
			case VIGENERE_ERR_ALLOC_FAIL: throw std::bad_alloc();
			case VIGENERE_ERR_BAD_KEY: throw std::invalid_argument("invalid Vigenere key");
			default: throw std::runtime_error("Vigenere operation failed");
		}
	}

	static std::vector<std::uint8_t> make_vector(void *data,std::size_t len) {
		std::unique_ptr<std::uint8_t, decltype(&std::free)>
		buffer(static_cast<std::uint8_t *>(data),&std::free);
		if (len == 0) return {};
		return std::vector<std::uint8_t>(buffer.get(),buffer.get() + len);
	}
};

class Affine {
public:
	Affine(int a, int b) : a_(a), b_(b) {
		if (affine_validate_key(a_, b_) != AFFINE_SUCCESS) throw std::invalid_argument("invalid Affine key");
	}

	int a() const noexcept {
		return a_;
	}

	int b() const noexcept {
		return b_;
	}

	void set_key(int a, int b) {
		if (affine_validate_key(a, b) != AFFINE_SUCCESS) throw std::invalid_argument("invalid Affine key");
		a_ = a;
		b_ = b;
	}

	char encrypt(char c) const noexcept {
		return affine_encrypt_char(c, a_, b_);
	}

	char decrypt(char c) const noexcept {
		return affine_decrypt_char(c, a_, b_);
	}

	void encrypt_inplace(std::string& text) const {
#if __cplusplus >= 201703L
		const int rc = affine_encrypt_inplace(text.data(), a_, b_);
#else
		const int rc = affine_encrypt_inplace(&text[0], a_, b_);
#endif
		if (rc == AFFINE_ERR_BAD_KEY) throw std::invalid_argument("invalid Affine key");
		if (rc != AFFINE_SUCCESS) throw std::invalid_argument("invalid input");
	}

	void decrypt_inplace(std::string& text) const {
#if __cplusplus >= 201703L
		const int rc = affine_decrypt_inplace(text.data(), a_, b_);
#else
		const int rc = affine_decrypt_inplace(&text[0], a_, b_);
#endif
		if (rc == AFFINE_ERR_BAD_KEY) throw std::invalid_argument("invalid Affine key");
		if (rc != AFFINE_SUCCESS) throw std::invalid_argument("invalid input");
	}

	std::string encrypt(const char *text) const {
		if (!text) throw std::invalid_argument("null string");
		char *result = nullptr;
		const int rc = affine_encrypt(text, a_, b_, &result);
		if (rc == AFFINE_ERR_BAD_KEY) throw std::invalid_argument("invalid Affine key");
		if (rc == AFFINE_ERR_ALLOC_FAIL) throw std::bad_alloc();
		if (rc != AFFINE_SUCCESS) throw std::invalid_argument("invalid input");
		std::unique_ptr<char, decltype(&std::free)>
		buffer(result, &std::free);
		return std::string(buffer.get());
	}

	std::string decrypt(const char *text) const {
		if (!text) throw std::invalid_argument("null string");
		char *result = nullptr;
		const int rc = affine_decrypt(text, a_, b_, &result);
		if (rc == AFFINE_ERR_BAD_KEY) throw std::invalid_argument("invalid Affine key");
		if (rc == AFFINE_ERR_ALLOC_FAIL) throw std::bad_alloc();
		if (rc != AFFINE_SUCCESS) throw std::invalid_argument("invalid input");
		std::unique_ptr<char, decltype(&std::free)> buffer(result, &std::free);
		return std::string(buffer.get());
	}

	std::string encrypt(const std::string& text) const {
		return encrypt(text.c_str());
	}

	std::string decrypt(const std::string& text) const {
		return decrypt(text.c_str());
	}

	void encrypt(const std::uint8_t *input,std::size_t length,std::uint8_t *output) const {
		const int rc = affine_encrypt_buffer(input,length,a_,b_,output);
		check_result(rc);
	}

	void decrypt(const std::uint8_t *input,std::size_t length,std::uint8_t *output) const {
		const int rc = affine_decrypt_buffer(input,length,a_,b_,output);
		check_result(rc);
	}

	std::vector<std::uint8_t> encrypt(const std::vector<std::uint8_t>& input) const {
		std::vector<std::uint8_t> output(input.size());
		encrypt(input.data(),input.size(),output.data());
		return output;
	}

	std::vector<std::uint8_t> decrypt(const std::vector<std::uint8_t>& input) const {
		std::vector<std::uint8_t> output(input.size());
		decrypt(input.data(),input.size(),output.data());
		return output;
	}

private:
	int a_;
	int b_;
	static void check_result(int rc) {
		switch (rc) {
			case AFFINE_SUCCESS: return;
			case AFFINE_ERR_INVALID_ARG: throw std::invalid_argument("invalid input");
			case AFFINE_ERR_BAD_KEY: throw std::invalid_argument("invalid Affine key");
			case AFFINE_ERR_ALLOC_FAIL: throw std::bad_alloc();
			default: throw std::runtime_error("Affine operation failed");
		}
	}
};

class Atbash {
public:
	char transform(char c) const noexcept {
		return atbash_char(c);
	}

	char encrypt(char c) const noexcept {
		return atbash_char(c);
	}

	char decrypt(char c) const noexcept {
		return atbash_char(c);
	}

	void transform_inplace(char *data, std::size_t len) const {
		check_result(atbash_inplace(data, len));
	}

	void encrypt_inplace(char *data, std::size_t len) const {
		check_result(atbash_encrypt_inplace(data, len));
	}

	void decrypt_inplace(char *data, std::size_t len) const {
		check_result(atbash_decrypt_inplace(data, len));
	}

	void transform_inplace(std::string& text) const {
#if __cplusplus >= 201703L
		transform_inplace(text.data(), text.size());
#else
		transform_inplace(&text[0], text.size());
#endif
	}

	void encrypt_inplace(std::string& text) const {
#if __cplusplus >= 201703L
		encrypt_inplace(text.data(), text.size());
#else
		encrypt_inplace(&text[0], text.size());
#endif
	}

	void decrypt_inplace(std::string& text) const {
#if __cplusplus >= 201703L
		decrypt_inplace(text.data(), text.size());
#else
		decrypt_inplace(&text[0], text.size());
#endif
	}

	std::string transform(const char *text) const {
		return transform_string(text, atbash);
	}

	std::string encrypt(const char *text) const {
		return transform(text);
	}

	std::string decrypt(const char *text) const {
		return transform(text);
	}

	std::string transform(const std::string& text) const {
		return transform(text.c_str());
	}

	std::string encrypt(const std::string& text) const {
		return transform(text);
	}

	std::string decrypt(const std::string& text) const {
		return transform(text);
	}

	std::vector<std::uint8_t> transform(const void *data,std::size_t len) const {
		return transform_buffer(data, len, atbash_buffer);
	}

	std::vector<std::uint8_t> encrypt(const void *data,std::size_t len) const {
		return transform(data, len);
	}

	std::vector<std::uint8_t> decrypt(const void *data,std::size_t len) const {
		return transform(data, len);
	}

	std::vector<std::uint8_t> transform(const std::vector<std::uint8_t>& data) const {
		return transform(data.data(), data.size());
	}

	std::vector<std::uint8_t> encrypt(const std::vector<std::uint8_t>& data) const {
		return transform(data);
	}

	std::vector<std::uint8_t> decrypt(const std::vector<std::uint8_t>& data) const {
		return transform(data);
	}

private:
	template <typename Function>
	static std::string transform_string(const char *text,Function function) {
		if (!text) throw std::invalid_argument("null string");
		char *result = function(text);
		if (!result) throw std::bad_alloc();
		std::unique_ptr<char, decltype(&std::free)> buffer(result, &std::free);
		return std::string(buffer.get());
	}

	template <typename Function>
	static std::vector<std::uint8_t> transform_buffer(const void *data,std::size_t len,Function function) {
		void *result = nullptr;
		const int rc = function(data, len, &result);
		check_result(rc);
		std::unique_ptr<std::uint8_t, decltype(&std::free)> buffer(static_cast<std::uint8_t *>(result),&std::free);
		if (len == 0) return {};
		return std::vector<std::uint8_t>(buffer.get(),buffer.get() + len);
	}

	static void check_result(int rc) {
		switch (rc) {
			case ATBASH_SUCCESS: return;
			case ATBASH_ERR_INVALID_ARG: throw std::invalid_argument("invalid Atbash input");
			case ATBASH_ERR_ALLOC_FAIL: throw std::bad_alloc();
			default: throw std::runtime_error("Atbash operation failed");
		}
	}
};

class Playfair {
public:
	explicit Playfair(const std::string& key)
	: key_(key) {
		if (playfair_build_matrix(key_.c_str(), matrix_) != PLAYFAIR_SUCCESS) throw std::invalid_argument("invalid Playfair key");
	}

	const std::string& key() const noexcept {
		return key_;
	}

	void set_key(const std::string& key) {
		char matrix[25];
		if (playfair_build_matrix(key.c_str(), matrix) != PLAYFAIR_SUCCESS) throw std::invalid_argument("invalid Playfair key");
		key_ = key;
		std::copy(std::begin(matrix), std::end(matrix), std::begin(matrix_));
	}

	char normalize(char c) const noexcept {
		return playfair_normalize_char(c);
	}

	std::string matrix() const {
		return std::string(matrix_, sizeof(matrix_));
	}

	std::string encrypt(const char* text) const {
		if (!text) throw std::invalid_argument("null text");
		std::unique_ptr<char, decltype(&std::free)> result(playfair_encrypt(text, key_.c_str()), &std::free);
		if (!result) throw std::runtime_error("Playfair encryption failed");
		return std::string(result.get());
	}

	std::string decrypt(const char* text) const {
		if (!text) throw std::invalid_argument("null text");
		std::unique_ptr<char, decltype(&std::free)> result(playfair_decrypt(text, key_.c_str()), &std::free);
		if (!result) throw std::runtime_error("Playfair decryption failed");
		return std::string(result.get());
	}

	std::string encrypt(const std::string& text) const {
		return encrypt(text.c_str());
	}

	std::string decrypt(const std::string& text) const {
		return decrypt(text.c_str());
	}

	void encrypt_inplace(std::string& text) const {
#if __cplusplus >= 201703L
		const int rc = playfair_encrypt_inplace(text.data(),text.size(),key_.c_str());
#else
		const int rc = playfair_encrypt_inplace(&text[0],text.size(),key_.c_str());
#endif
		check_result(rc);
	}

	void decrypt_inplace(std::string& text) const {
#if __cplusplus >= 201703L
		const int rc = playfair_decrypt_inplace(text.data(),text.size(),key_.c_str());
#else
		const int rc = playfair_decrypt_inplace(&text[0],text.size(),key_.c_str());
#endif
		check_result(rc);
	}

	std::vector<std::uint8_t> encrypt(const std::vector<std::uint8_t>& input) const {
		std::string text(reinterpret_cast<const char*>(input.data()),input.size());
		text = encrypt(text);
		return std::vector<std::uint8_t>(
			reinterpret_cast<const std::uint8_t*>(text.data()),
			reinterpret_cast<const std::uint8_t*>(text.data()) + text.size()
		);
	}

	std::vector<std::uint8_t> decrypt(const std::vector<std::uint8_t>& input) const {
		std::string text(reinterpret_cast<const char*>(input.data()),input.size());
		text = decrypt(text);
		return std::vector<std::uint8_t>(
			reinterpret_cast<const std::uint8_t*>(text.data()),
			reinterpret_cast<const std::uint8_t*>(text.data()) + text.size()
		);
	}

	void encrypt_pair(char a,char b,char& out_a,char& out_b) const {
		check_result(playfair_encrypt_pair(matrix_,a,b,&out_a,&out_b));
	}

	void decrypt_pair(char a,char b,char& out_a,char& out_b) const {
		check_result(playfair_decrypt_pair(matrix_,a,b,&out_a,&out_b));
	}

	static void remove_padding(std::string& text) {
		if (text.empty()) return;
		size_t len = text.size();
#if __cplusplus >= 201703L
		playfair_remove_padding(text.data(), &len);
#else
		playfair_remove_padding(&text[0], &len);
#endif
		text.resize(len);
	}

private:
	std::string key_;
	char matrix_[25]{};

	static void check_result(int rc) {
		switch (rc) {
			case PLAYFAIR_SUCCESS: return;
			case PLAYFAIR_ERR_INVALID_ARG: throw std::invalid_argument("invalid Playfair argument");
			case PLAYFAIR_ERR_ALLOC_FAIL: throw std::bad_alloc();
			case PLAYFAIR_ERR_BAD_KEY: throw std::invalid_argument("invalid Playfair key");
			case PLAYFAIR_ERR_BAD_TEXT: throw std::invalid_argument("invalid Playfair text");
			default: throw std::runtime_error("Playfair operation failed");
		}
	}
};

class CustomCipher {
public:
	using encrypt_callback =
		std::function<int(const void*,std::size_t,void**,std::size_t*)>;
	using decrypt_callback =
		std::function<int(const void*,std::size_t,void**,std::size_t*)>;

	using encrypt_vector_callback =
		std::function<int(const std::vector<std::uint8_t>&,void**,std::size_t*)>;
	using decrypt_vector_callback =
		std::function<int(const std::vector<std::uint8_t>&,void**,std::size_t*)>;

	using encrypt_string_callback =
		std::function<int(const std::string&,void**,std::size_t*)>;
	using decrypt_string_callback =
		std::function<int(const std::string&,void**,std::size_t*)>;

	CustomCipher(encrypt_callback encrypt,
	             decrypt_callback decrypt) {
		encrypt_instance() = std::move(encrypt);
		decrypt_instance() = std::move(decrypt);

		if (!encrypt_instance() || !decrypt_instance())
			throw std::invalid_argument("invalid custom cipher callback");

		if (customcipher_init(&cipher_,
		                      encrypt_trampoline,
		                      decrypt_trampoline) != CUSTOMCIPHER_SUCCESS) {
			throw std::invalid_argument("invalid custom cipher callbacks");
		}
	}

	CustomCipher(encrypt_vector_callback encrypt,
	             decrypt_vector_callback decrypt) {
		if (!encrypt || !decrypt)
			throw std::invalid_argument("invalid custom cipher callback");

		encrypt_instance() = [encrypt](const void* input,
		                     std::size_t input_size,
		                     void** output,
		                     std::size_t* output_size) -> int {
			const std::uint8_t* data =
				static_cast<const std::uint8_t*>(input);

			std::vector<std::uint8_t> buffer(data,data + input_size);
			return encrypt(buffer,output,output_size);
		};

		decrypt_instance() = [decrypt](const void* input,
		                     std::size_t input_size,
		                     void** output,
		                     std::size_t* output_size) -> int {
			const std::uint8_t* data =
				static_cast<const std::uint8_t*>(input);

			std::vector<std::uint8_t> buffer(data,data + input_size);
			return decrypt(buffer,output,output_size);
		};

		if (customcipher_init(&cipher_,
		                      encrypt_trampoline,
		                      decrypt_trampoline) != CUSTOMCIPHER_SUCCESS) {
			throw std::invalid_argument("invalid custom cipher callbacks");
		}
	}

	CustomCipher(encrypt_string_callback encrypt,decrypt_string_callback decrypt) {
		if (!encrypt || !decrypt) throw std::invalid_argument("invalid custom cipher callback");
		encrypt_instance() = [encrypt](const void* input,std::size_t input_size,void** output,std::size_t* output_size) -> int {
			const char* data = static_cast<const char*>(input);
			std::string buffer(data,input_size);
			return encrypt(buffer,output,output_size);
		};
		decrypt_instance() = [decrypt](const void* input,std::size_t input_size,void** output,std::size_t* output_size) -> int {
			const char* data = static_cast<const char*>(input);
			std::string buffer(data,input_size);
			return decrypt(buffer,output,output_size);
		};
		if (customcipher_init(&cipher_,encrypt_trampoline,decrypt_trampoline) != CUSTOMCIPHER_SUCCESS) {
			throw std::invalid_argument("invalid custom cipher callbacks");
		}
	}

	int encrypt(const void* data,std::size_t len,void** out,std::size_t* out_len) const {
		return customcipher_encrypt(&cipher_,data,len,out,out_len);
	}

	int decrypt(const void* data,std::size_t len,void** out,std::size_t* out_len) const {
		return customcipher_decrypt(&cipher_,data,len,out,out_len);
	}

	int encrypt(const char* data,std::size_t len,char** out,std::size_t* out_len) const {
		return customcipher_encrypt_string(&cipher_,data,len,out,out_len);
	}

	int decrypt(const char* data,std::size_t len,char** out,std::size_t* out_len) const {
		return customcipher_decrypt_string(&cipher_,data,len,out,out_len);
	}

	std::vector<std::uint8_t> encrypt(const std::vector<std::uint8_t>& data) const {
		void* out = nullptr;
		std::size_t out_len = 0;
		check_result(encrypt(data.data(),data.size(),&out,&out_len));
		std::unique_ptr<void,decltype(&std::free)> buffer(out,&std::free);
		const std::uint8_t* begin = static_cast<const std::uint8_t*>(buffer.get());
		return std::vector<std::uint8_t>(begin,begin + out_len);
	}

	std::vector<std::uint8_t> decrypt(const std::vector<std::uint8_t>& data) const {
		void* out = nullptr;
		std::size_t out_len = 0;
		check_result(decrypt(data.data(),data.size(),&out,&out_len));
		std::unique_ptr<void,decltype(&std::free)> buffer(out,&std::free);
		const std::uint8_t* begin = static_cast<const std::uint8_t*>(buffer.get());
		return std::vector<std::uint8_t>(begin,begin + out_len);
	}

	std::string encrypt(const std::string& data) const {
		char* out = nullptr;
		std::size_t out_len = 0;
		check_result(encrypt(data.data(),data.size(),&out,&out_len));
		std::unique_ptr<char,decltype(&std::free)> buffer(out,&std::free);
		return std::string(buffer.get(),out_len);
	}

	std::string decrypt(const std::string& data) const {
		char* out = nullptr;
		std::size_t out_len = 0;
		check_result(decrypt(data.data(),data.size(),&out,&out_len));
		std::unique_ptr<char,decltype(&std::free)> buffer(out,&std::free);
		return std::string(buffer.get(),out_len);
	}

	const customcipher* native_handle() const noexcept {
		return &cipher_;
	}

private:
	customcipher cipher_;
	static encrypt_callback& encrypt_instance() {
		static encrypt_callback callback;
		return callback;
	}

	static decrypt_callback& decrypt_instance() {
		static decrypt_callback callback;
		return callback;
	}

	static int encrypt_trampoline(const void* input,std::size_t input_size,void** output,std::size_t* output_size) {
		encrypt_callback& callback = encrypt_instance();
		if (!callback) return CUSTOMCIPHER_ERR_INVALID_ARG;
		return callback(input,input_size,output,output_size);
	}

	static int decrypt_trampoline(const void* input,std::size_t input_size,void** output,std::size_t* output_size) {
		decrypt_callback& callback = decrypt_instance();
		if (!callback) return CUSTOMCIPHER_ERR_INVALID_ARG;
		return callback(input,input_size,output,output_size);
	}

	static void check_result(int rc) {
		switch (rc) {
			case CUSTOMCIPHER_SUCCESS: return;
			case CUSTOMCIPHER_ERR_INVALID_ARG: throw std::invalid_argument("invalid custom cipher argument");
			case CUSTOMCIPHER_ERR_ALLOC_FAIL: throw std::bad_alloc();
			case CUSTOMCIPHER_ERR_BAD_KEY: throw std::invalid_argument("invalid custom cipher key");
			case CUSTOMCIPHER_ERR_BAD_DATA: throw std::invalid_argument("invalid custom cipher data");
			default: throw std::runtime_error("custom cipher operation failed");
		}
	}
};

} // namespace cipher

} // namespace hash

#endif // CIPHER_HPP
