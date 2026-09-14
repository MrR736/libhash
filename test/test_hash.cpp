#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "hash.hpp"

#ifndef LIBHASH_CXX_STANDARD
#define LIBHASH_CXX_STANDARD "11"
#endif

namespace {

void test(bool condition, const char* message) {
	if (!condition) {
		std::cerr << "[FAIL] " << message << std::endl;
		std::abort();
	}
	std::cout << "[ OK ] " << message << std::endl;
}

template <typename T>
bool equal_object(const T& a, const T& b) {
	return std::memcmp(&a, &b, sizeof(T)) == 0;
}

std::string hex_encode(const std::uint8_t* data, std::size_t size) {
	static const char digits[] = "0123456789abcdef";
	std::string result;
	result.reserve(size * 2);
	for (std::size_t i = 0; i < size; ++i) {
		const std::uint8_t value = data[i];
		result.push_back(digits[(value >> 4) & 0x0f]);
		result.push_back(digits[value & 0x0f]);
	}
	return result;
}

template <typename T>
std::string object_hex(const T& value) {
	return hex_encode(
		reinterpret_cast<const std::uint8_t*>(&value),
		sizeof(T));
}

void test_md2() {
	const std::string input = "abc";
	hash::Md2 incremental;
	incremental.update(input);
	const hash::Md2::digest_type one_shot = hash::Md2::calculate(input);
	const hash::Md2::digest_type& finalized = incremental.finalize();
	test(equal_object(finalized, one_shot),"MD2 incremental == one-shot");
	test(equal_object(incremental.digest(), finalized),"MD3 digest() == finalize()");
}

void test_md4() {
	const std::string input = "abc";
	hash::Md4 incremental;
	incremental.update(input);
	const hash::Md4::digest_type one_shot = hash::Md4::calculate(input);
	const hash::Md4::digest_type& finalized = incremental.finalize();
	test(equal_object(finalized, one_shot),"MD4 incremental == one-shot");
	test(equal_object(incremental.digest(), finalized),"MD4 digest() == finalize()");
}

void test_md5() {
	const std::string input = "abc";
	hash::Md5 incremental;
	incremental.update(input.data(), 1);
	incremental.update(input.data() + 1, input.size() - 1);
	const hash::Md5::digest_type one_shot = hash::Md5::calculate(input);
	const hash::Md5::digest_type& finalized = incremental.finalize();
	test(equal_object(finalized, one_shot),"MD5 incremental == one-shot");
	test(equal_object(incremental.digest(), finalized),"MD5 digest() == finalize()");
}

void test_sha0() {
	const std::string input = "The quick brown fox jumps over the lazy dog";
	hash::Sha0 incremental;
	incremental.update(input.data(),10);
	incremental.update(input.data() + 10,input.size() - 10);
	const hash::Sha0::digest_type one_shot = hash::Sha0::calculate(input);
	test(equal_object(incremental.finalize(), one_shot),"SHA0 incremental == one-shot");
}

void test_sha1() {
	const std::string input = "The quick brown fox jumps over the lazy dog";
	hash::Sha1 incremental;
	incremental.update(input.data(),10);
	incremental.update(input.data() + 10,input.size() - 10);
	const hash::Sha1::digest_type one_shot = hash::Sha1::calculate(input);
	test(equal_object(incremental.finalize(), one_shot),"SHA1 incremental == one-shot");
}

void test_sha224() {
	const std::string input = "The quick brown fox jumps over the lazy dog";
	hash::Sha224 incremental;
	incremental.update(input);
	const hash::Sha224::digest_type one_shot = hash::Sha224::calculate(input);
	test(equal_object(incremental.finalize(), one_shot),"SHA224 incremental == one-shot");
}

void test_sha256() {
	const std::string input = "The quick brown fox jumps over the lazy dog";
	hash::Sha256 incremental;
	incremental.update(input.data(), 3);
	incremental.update(input.data() + 3, 7);
	incremental.update(input.data() + 10, input.size() - 10);
	const hash::Sha256::digest_type one_shot = hash::Sha256::calculate(input);
	test(equal_object(incremental.finalize(), one_shot),"SHA256 incremental == one-shot");
}

void test_sha384() {
	const std::string input = "The quick brown fox jumps over the lazy dog";
	hash::Sha384 incremental;
	incremental.update(input);
	const hash::Sha384::digest_type one_shot = hash::Sha384::calculate(input);
	test(equal_object(incremental.finalize(), one_shot),"SHA384 incremental == one-shot");
}

void test_sha512() {
	const std::string input = "The quick brown fox jumps over the lazy dog";
	hash::Sha512 incremental;
	incremental.update(input.data(), 5);
	incremental.update(input.data() + 5, input.size() - 5);
	const hash::Sha512::digest_type one_shot = hash::Sha512::calculate(input);
	test(equal_object(incremental.finalize(), one_shot),"SHA512 incremental == one-shot");
}

void test_sha3_256() {
	const std::string input = "The quick brown fox jumps over the lazy dog";
	hash::Sha3_256 incremental;
	incremental.update(input.data(), 5);
	incremental.update(input.data() + 5, input.size() - 5);
	const hash::Sha3_256::digest_type one_shot = hash::Sha3_256::calculate(input);
	test(equal_object(incremental.finalize(), one_shot),"SHA3-256 incremental == one-shot");
}

void test_sha3_512() {
	const std::string input = "The quick brown fox jumps over the lazy dog";
	hash::Sha3_512 incremental;
	incremental.update(input.data(), 5);
	incremental.update(input.data() + 5, input.size() - 5);
	const hash::Sha3_512::digest_type one_shot = hash::Sha3_512::calculate(input);
	test(equal_object(incremental.finalize(), one_shot),"SHA3-512 incremental == one-shot");
}

void test_sha512_224() {
	const std::string input = "The quick brown fox jumps over the lazy dog";
	hash::Sha512_224 incremental;
	incremental.update(input.data(), 5);
	incremental.update(input.data() + 5, input.size() - 5);
	const hash::Sha512_224::digest_type one_shot = hash::Sha512_224::calculate(input);
	test(equal_object(incremental.finalize(), one_shot),"SHA512/224 incremental == one-shot");
}

void test_sha512_256() {
	const std::string input = "The quick brown fox jumps over the lazy dog";
	hash::Sha512_256 incremental;
	incremental.update(input.data(), 5);
	incremental.update(input.data() + 5, input.size() - 5);
	const hash::Sha512_256::digest_type one_shot = hash::Sha512_256::calculate(input);
	test(equal_object(incremental.finalize(), one_shot),"SHA512/256 incremental == one-shot");
}

void test_digests() {
	std::cout << "\n== Digest tests ==\n";
	test_md2();
	test_md4();
	test_md5();
	test_sha0();
	test_sha1();
	test_sha224();
	test_sha256();
	test_sha384();
	test_sha512();
	test_sha3_256();
	test_sha3_512();
	test_sha512_224();
	test_sha512_256();
}

void test_base16() {
	std::cout << "\n== Base16 tests ==\n";
	const std::string input = "Hello World!";
	const std::string encoded = hash::Base16::encode(input);
	const std::vector<std::uint8_t> decoded = hash::Base16::decode(encoded);
	test(decoded.size() == input.size(),"Base16 decoded size");
	test(std::memcmp(decoded.data(),input.data(),input.size()) == 0,"Base16 round-trip");
	base16_config_t cfg = {"0123456789ABCDEF",0};
	const std::string custom = hash::Base16::encode_custom(input,cfg);
	const std::vector<std::uint8_t> custom_decoded = hash::Base16::decode_custom(custom,cfg);
	test(
		custom_decoded.size() == input.size(),
		"Base16 custom decoded size");
	test(
		std::memcmp(
			custom_decoded.data(),
			input.data(),
			input.size()) == 0,
		"Base16 custom round-trip");
}

void test_base32() {
	std::cout << "\n== Base32 tests ==\n";
	const std::string input = "hello world";
	const std::string encoded = hash::Base32::encode(input);
	const std::vector<std::uint8_t> decoded = hash::Base32::decode(encoded);
	test(decoded.size() == input.size(),"Base32 decoded size");
	test(std::memcmp(decoded.data(),input.data(),input.size()) == 0,"Base32 round-trip");
	const std::string crockford = hash::Base32::encode_crockford(input);
	const std::vector<std::uint8_t> crockford_decoded = hash::Base32::decode_crockford(crockford);
	test(crockford_decoded.size() == input.size(),"Base32 Crockford round-trip");
	const std::string zbase = hash::Base32::encode_zbase32(input);
	const std::vector<std::uint8_t> zbase_decoded = hash::Base32::decode_zbase32(zbase);
	test(zbase_decoded.size() == input.size(),"Base32 z-base-32 round-trip");
	const std::string hex = hash::Base32::encode_hex(input);
	const std::vector<std::uint8_t> hex_decoded = hash::Base32::decode_hex(hex);
	test(hex_decoded.size() == input.size(),"Base32 hex round-trip");
}

void test_base58() {
	std::cout << "\n== Base58 tests ==\n";
	const std::string input = "Hello World!";
	const std::vector<std::uint8_t> bytes(input.begin(),input.end());
	const std::string encoded = hash::Base58::encode(bytes);
	const std::vector<std::uint8_t> decoded = hash::Base58::decode(encoded);
	test(decoded == bytes,"Base58 round-trip");
	const std::string btc = hash::Base58::encode_bitcoin(bytes);
	test(hash::Base58::decode_bitcoin(btc) == bytes,"Base58 Bitcoin round-trip");
	const std::string ripple = hash::Base58::encode_ripple(bytes);
	test(hash::Base58::decode_ripple(ripple) == bytes,"Base58 Ripple round-trip");
	const std::string flickr = hash::Base58::encode_flickr(bytes);
	test(hash::Base58::decode_flickr(flickr) == bytes,"Base58 Flickr round-trip");
}

void test_base64() {
	std::cout << "\n== Base64 tests ==\n";
	const std::string input = "The quick brown fox jumps over the lazy dog";
	const std::string encoded = hash::Base64::encode(input);
	const std::vector<std::uint8_t> decoded = hash::Base64::decode(encoded);
	test(decoded.size() == input.size(),"Base64 decoded size");
	test(std::memcmp(decoded.data(),input.data(),input.size()) == 0,"Base64 round-trip");
	const std::string url = hash::Base64::encode_url(input);
	const std::vector<std::uint8_t> url_decoded = hash::Base64::decode_url(url);
	test(url_decoded.size() == input.size(),"Base64 URL round-trip");
	const std::string mime = hash::Base64::encode_mime(input);
	const std::vector<std::uint8_t> mime_decoded = hash::Base64::decode_mime(mime);
	test(mime_decoded.size() == input.size(),"Base64 MIME round-trip");
}

void test_encodings() {
	test_base16();
	test_base32();
	test_base58();
	test_base64();
}


void test_crc8() {
	std::cout << "\n== CRC8 tests ==\n";
	const std::string input = "123456789";
	hash::Crc8 crc(hash::Crc8::Variant::SMBUS,false);
	const std::uint8_t value = crc.compute(input);
	/*
	 * Standard CRC-8/SMBUS test vector:
	 *
	 * "123456789" -> 0xF4
	 */
	test(value == 0xF4U,"CRC8 SMBUS known vector");
	const std::vector<std::uint8_t> bytes(input.begin(),input.end());
	test(crc.compute(bytes) == value,"CRC8 vector overload");
	test(crc.compute(input) == value,"CRC8 string overload");
}

void test_crc16() {
	std::cout << "\n== CRC16 tests ==\n";
	const std::string input = "123456789";
	hash::Crc16 crc(hash::Crc16::Variant::IBM,true);
	const std::uint16_t value = crc.compute(input);
	/*
	 * Standard CRC-16/IBM test vector:
	 *
	 * "123456789" -> 0xBB3D
	 */
	test(value == 0xBB3DU,"CRC16 IBM known vector");
	const std::vector<std::uint8_t> bytes(input.begin(),input.end());
	test(crc.compute(bytes) == value,"CRC16 vector overload");
	test(crc.compute(input) == value,"CRC16 string overload");
}

void test_crc32() {
	std::cout << "\n== CRC32 tests ==\n";
	const std::string input = "123456789";
	hash::Crc32 crc(hash::Crc32::Variant::IEEE,true);
	const std::uint32_t value = crc.compute(input);
	/*
	 * Standard CRC-32/ISO-HDLC test vector:
	 *
	 * "123456789" -> 0xCBF43926
	 */
	test(value == 0xCBF43926U,"CRC32 IEEE known vector");
	const std::vector<std::uint8_t> bytes(input.begin(),input.end());
	test(crc.compute(bytes) == value,"CRC32 vector overload");
	test(crc.compute(input) == value,"CRC32 string overload");
}

void test_crc64() {
	std::cout << "\n== CRC64 tests ==\n";
	const std::string input = "123456789";
	hash::Crc64 crc(hash::Crc64::Variant::ECMA,false);
	const std::uint64_t value = crc.compute(input);
	/*
	 * Standard CRC-64/ECMA test vector:
	 *
	 * "123456789" -> 0x6C40DF5F0B497347
	 */
	test(value == 0x6C40DF5F0B497347ULL,"CRC64 ECMA known vector");
	const std::vector<std::uint8_t> bytes(input.begin(),input.end());
	test(crc.compute(bytes) == value,"CRC64 vector overload");
	test(crc.compute(input) == value,"CRC64 string overload");
}

void test_aes() {
	std::cout << "\n== AES tests ==\n";
	/*
	 * AES-128 known-answer test.
	 *
	 * Key:
	 *   000102030405060708090a0b0c0d0e0f
	 *
	 * Plaintext:
	 *   00112233445566778899aabbccddeeff
	 *
	 * Ciphertext:
	 *   69c4e0d86a7b0430d8cdb78070b4c55a
	 */
	const std::uint8_t key[16] = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f
	};
	const std::uint8_t plaintext[16] = {
		0x00, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb,
		0xcc, 0xdd, 0xee, 0xff
	};
	const std::uint8_t expected[16] = {
		0x69, 0xc4, 0xe0, 0xd8,
		0x6a, 0x7b, 0x04, 0x30,
		0xd8, 0xcd, 0xb7, 0x80,
		0x70, 0xb4, 0xc5, 0x5a
	};
	std::uint8_t ciphertext[16] = {};
	std::uint8_t decrypted[16] = {};
	hash::Aes aes(key, sizeof(key));
	aes.encrypt(
		plaintext,
		ciphertext);
	test(
		std::memcmp(ciphertext, expected, 16) == 0,
		"AES-128 known-answer encryption");
	aes.decrypt(
		ciphertext,
		decrypted);
	test(
		std::memcmp(decrypted, plaintext, 16) == 0,
		"AES-128 decryption");
}

void test_aes_cbc() {
	std::cout << "\n== AES-CBC tests ==\n";
	const std::vector<std::uint8_t> key = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f
	};
	const hash::AesCbc::iv_type iv = {
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00
	};
	const std::uint8_t plaintext[32] = {
		0x00, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb,
		0xcc, 0xdd, 0xee, 0xff,
		0xff, 0xee, 0xdd, 0xcc,
		0xbb, 0xaa, 0x99, 0x88,
		0x77, 0x66, 0x55, 0x44,
		0x33, 0x22, 0x11, 0x00
	};
	std::uint8_t encrypted[32] = {};
	std::uint8_t decrypted[32] = {};
	hash::AesCbc encryptor(key, iv);
	hash::AesCbc decryptor(key, iv);
	encryptor.encrypt(plaintext,encrypted,sizeof(plaintext));
	test(std::memcmp(encrypted,plaintext,sizeof(plaintext)) != 0,"AES-CBC encryption modifies plaintext");
	decryptor.decrypt(encrypted,decrypted,sizeof(plaintext));
	test(std::memcmp(decrypted,plaintext,sizeof(plaintext)) == 0,"AES-CBC encrypt/decrypt round-trip");
}

void test_aes_ctr() {
	std::cout << "\n== AES-CTR tests ==\n";
	const std::vector<std::uint8_t> key = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f
	};
	const hash::AesCtr::iv_type iv = {};
	const std::string input =
	"AES CTR mode test data";
	const std::vector<std::uint8_t> plaintext(
		input.begin(),
											  input.end());
	std::vector<std::uint8_t> encrypted(
		plaintext.size());
	std::vector<std::uint8_t> decrypted(
		plaintext.size());
	hash::AesCtr encryptor(key, iv);
	hash::AesCtr decryptor(key, iv);
	encryptor.xor_stream(
		plaintext.data(),
						 encrypted.data(),
						 plaintext.size());
	test(
		encrypted != plaintext,
		 "AES-CTR modifies plaintext");
	decryptor.xor_stream(
		encrypted.data(),
						 decrypted.data(),
						 encrypted.size());
	test(
		decrypted == plaintext,
		 "AES-CTR encrypt/decrypt round-trip");
}

void test_aes_ofb() {
	std::cout << "\n== AES-OFB tests ==\n";
	const std::vector<std::uint8_t> key = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f
	};
	const hash::AesOfb::iv_type iv = {};
	const std::string input =
	"AES OFB mode test data";
	const std::vector<std::uint8_t> plaintext(
		input.begin(),
											  input.end());
	std::vector<std::uint8_t> encrypted(
		plaintext.size());
	std::vector<std::uint8_t> decrypted(
		plaintext.size());
	hash::AesOfb encryptor(key, iv);
	hash::AesOfb decryptor(key, iv);
	encryptor.xor_stream(
		plaintext.data(),
						 encrypted.data(),
						 plaintext.size());
	test(
		encrypted != plaintext,
		 "AES-OFB modifies plaintext");
	decryptor.xor_stream(
		encrypted.data(),
						 decrypted.data(),
						 encrypted.size());
	test(
		decrypted == plaintext,
		 "AES-OFB encrypt/decrypt round-trip");
}

void test_aes_modes() {
	test_aes();
	test_aes_cbc();
	test_aes_ctr();
	test_aes_ofb();
}

void test_rc4() {
	std::cout << "\n== RC4 tests ==\n";
	const std::uint8_t key[] = {
		0x4b, 0x65, 0x79
	};
	const std::string plaintext =
	"Plaintext";
	 const std::vector<std::uint8_t> original(
		 plaintext.begin(),
											  plaintext.end());
	 std::vector<std::uint8_t> encrypted(
		 original.size());
	 std::vector<std::uint8_t> decrypted(
		 original.size());
	 hash::Rc4 encryptor(
		 key,
		 sizeof(key));
	 encryptor.xor_stream(
		 original.data(),
						  encrypted.data(),
						  original.size());
	 test(
		 encrypted != original,
		  "RC4 modifies plaintext");
	 hash::Rc4 decryptor(
		 key,
		 sizeof(key));
	 decryptor.xor_stream(
		 encrypted.data(),
						  decrypted.data(),
						  encrypted.size());
	 test(
		 decrypted == original,
		  "RC4 encrypt/decrypt round-trip");
}

void test_errors() {
	std::cout << "\n== Error handling tests ==\n";
	bool caught = false;
	try { hash::Aes aes(nullptr, 16); }
	catch (const std::invalid_argument&) { caught = true; }
	test(caught,"AES rejects null key");
	caught = false;
	try { hash::Rc4 rc4(nullptr, 16); }
	catch (const std::invalid_argument&) { caught = true; }
	test(caught,"RC4 rejects null key");
}

} // namespace

int main() {
	try {
		std::cout << "hash.hpp C++" LIBHASH_CXX_STANDARD " test suite\n";
		std::cout << "========================\n";
		test_digests();
		test_encodings();
		test_crc8();
		test_crc16();
		test_crc32();
		test_crc64();
		test_aes_modes();
		test_rc4();
		test_errors();
		std::cout << "\n========================\n";
		std::cout << "All tests passed.\n";
		return 0;
	} catch (const std::exception& e) {
		std::cerr << "\n[EXCEPTION] " << e.what() << std::endl;
		return 1;
	} catch (...) {
		std::cerr << "\n[EXCEPTION] unknown exception" << std::endl;
		return 1;
	}
}
