#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "cipher.hpp"

#ifndef LIBHASH_CXX_STANDARD
#define LIBHASH_CXX_STANDARD "11"
#endif

using namespace hash::cipher;

static int tests = 0;
static int passed = 0;

static void check(bool condition, const char *name) {
	++tests;

	if (!condition) {
		std::cerr << "[FAIL] " << name << '\n';
		throw std::runtime_error(name);
	}

	++passed;
	std::cout << "[PASS] " << name << '\n';
}

static void check_equal(
	const std::string& actual,
	const std::string& expected,
	const char *name) {
	check(actual == expected, name);

	if (actual != expected) {
		std::cerr << "  expected: " << expected << '\n';
		std::cerr << "  actual:   " << actual << '\n';
	}
}

static void check_equal(
	const std::vector<std::uint8_t>& actual,
	const std::vector<std::uint8_t>& expected,
	const char *name) {
	check(actual == expected, name);
}

static std::vector<std::uint8_t> bytes(const char *text) {
	return std::vector<std::uint8_t>(
		reinterpret_cast<const std::uint8_t *>(text),
		reinterpret_cast<const std::uint8_t *>(text) + std::strlen(text)
	);
}

static void test_caesar() {
	std::cout << "\n=== Caesar ===\n";

	Caesar cipher(3);

	check(cipher.shift() == 3, "Caesar shift");

	check(cipher.encrypt('A') == 'D', "Caesar char encrypt");
	check(cipher.decrypt('D') == 'A', "Caesar char decrypt");

	check_equal(
		cipher.encrypt("Hello World!"),
				"Khoor Zruog!",
			 "Caesar string encrypt");

	check_equal(
		cipher.decrypt("Khoor Zruog!"),
				"Hello World!",
			 "Caesar string decrypt");

	std::string text = "Hello World!";
#if __cplusplus >= 201703L
	cipher.encrypt_inplace(text.data(), text.size());
#else
	cipher.encrypt_inplace(&text[0], text.size());
#endif

	check_equal(
		text,
		"Khoor Zruog!",
		"Caesar inplace encrypt");

#if __cplusplus >= 201703L
	cipher.decrypt_inplace(text.data(), text.size());
#else
	cipher.decrypt_inplace(&text[0], text.size());
#endif

	check_equal(
		text,
		"Hello World!",
		"Caesar inplace decrypt");

	std::vector<std::uint8_t> input = {
		0x00, 0x01, 0x41, 0x42, 0xFF
	};

	auto encrypted = cipher.encrypt(input);
	auto decrypted = cipher.decrypt(encrypted);

	check_equal(
		decrypted,
		input,
		"Caesar binary round trip");

	Caesar normalized(29);

	check(
		normalized.shift() == 3,
		  "Caesar shift normalization");

	std::vector<std::uint8_t> empty;

	check(
		cipher.encrypt(empty).empty(),
		  "Caesar empty vector");
}


static void test_vigenere() {
	std::cout << "\n=== Vigenere ===\n";

	Vigenere cipher("LEMON");

	check(
		cipher.key() == "LEMON",
		  "Vigenere key");

	check_equal(
		cipher.encrypt("ATTACKATDAWN"),
				"LXFOPVEFRNHR",
			 "Vigenere string encrypt");

	check_equal(
		cipher.decrypt("LXFOPVEFRNHR"),
				"ATTACKATDAWN",
			 "Vigenere string decrypt");

	std::string text = "ATTACKATDAWN";

	cipher.encrypt_inplace(text);

	check_equal(
		text,
		"LXFOPVEFRNHR",
		"Vigenere inplace encrypt");

	cipher.decrypt_inplace(text);

	check_equal(
		text,
		"ATTACKATDAWN",
		"Vigenere inplace decrypt");

	std::vector<std::uint8_t> input = bytes("ATTACKATDAWN");

	auto encrypted = cipher.encrypt(input);
	auto decrypted = cipher.decrypt(encrypted);

	check_equal(
		decrypted,
		input,
		"Vigenere binary round trip");

	bool threw = false;

	try {
		Vigenere invalid("123456");
	} catch (const std::invalid_argument&) {
		threw = true;
	}

	check(
		threw,
	   "Vigenere invalid key");

	threw = false;

	try {
		Vigenere invalid(nullptr);
	} catch (const std::invalid_argument&) {
		threw = true;
	}

	check(
		threw,
	   "Vigenere null key");
}


static void test_affine() {
	std::cout << "\n=== Affine ===\n";

	/*
	 * Standard example:
	 *
	 * E(x) = 5x + 8 mod 26
	 */
	Affine cipher(5, 8);

	check(cipher.a() == 5, "Affine a");
	check(cipher.b() == 8, "Affine b");

	check(
		cipher.encrypt('A') == 'I',
		  "Affine char encrypt");

	check(
		cipher.decrypt('I') == 'A',
		  "Affine char decrypt");

	const std::string input = "HELLO WORLD";

	const std::string encrypted = cipher.encrypt(input);
	const std::string decrypted = cipher.decrypt(encrypted);

	check_equal(
		decrypted,
		input,
		"Affine string round trip");

	std::string inplace = input;

	cipher.encrypt_inplace(inplace);

	check(
		inplace == encrypted,
	   "Affine inplace encrypt");

	cipher.decrypt_inplace(inplace);

	check_equal(
		inplace,
		input,
		"Affine inplace decrypt");

	std::vector<std::uint8_t> data = {
		0x00, 0x01, 0x41, 0x42, 0xFF
	};

	auto binary_encrypted = cipher.encrypt(data);
	auto binary_decrypted = cipher.decrypt(binary_encrypted);

	check_equal(
		binary_decrypted,
		data,
		"Affine binary round trip");

	bool threw = false;

	try {
		Affine invalid(2, 5);
	} catch (const std::invalid_argument&) {
		threw = true;
	}

	check(
		threw,
	   "Affine invalid key");

	cipher.set_key(7, 3);

	check(
		cipher.a() == 7 && cipher.b() == 3,
		  "Affine set key");
}


static void test_atbash() {
	std::cout << "\n=== Atbash ===\n";

	Atbash cipher;

	check(
		cipher.encrypt('A') == 'Z',
		  "Atbash char encrypt");

	check(
		cipher.decrypt('Z') == 'A',
		  "Atbash char decrypt");

	check_equal(
		cipher.encrypt("Hello World!"),
				"Svool Dliow!",
			 "Atbash string encrypt");

	check_equal(
		cipher.decrypt("Svool Dliow!"),
				"Hello World!",
			 "Atbash string decrypt");

	std::string text = "Hello World!";

	cipher.encrypt_inplace(text);

	check_equal(
		text,
		"Svool Dliow!",
		"Atbash inplace encrypt");

	cipher.decrypt_inplace(text);

	check_equal(
		text,
		"Hello World!",
		"Atbash inplace decrypt");

	std::vector<std::uint8_t> data = {
		0x00, 0x01, 'A', 'B', 'z', 0xFF
	};

	auto encrypted = cipher.encrypt(data);
	auto decrypted = cipher.decrypt(encrypted);

	check_equal(
		decrypted,
		data,
		"Atbash binary round trip");

	auto transformed = cipher.transform(data);

	check_equal(
		cipher.transform(transformed),
				data,
			 "Atbash transform round trip");
}


static void test_playfair() {
	std::cout << "\n=== Playfair ===\n";

	Playfair cipher("PLAYFAIR EXAMPLE");

	check(
		cipher.key() == "PLAYFAIR EXAMPLE",
		  "Playfair key");

	check(
		cipher.normalize('j') == 'I',
		  "Playfair J normalization");

	check(
		cipher.normalize('a') == 'A',
		  "Playfair character normalization");

	const std::string matrix = cipher.matrix();

	check(
		matrix.size() == 25,
		  "Playfair matrix size");

	check(
		matrix.find('J') == std::string::npos,
		  "Playfair matrix excludes J");

	const std::string plaintext = "HIDETHEGOLDINTHETREESTUMP";

	const std::string encrypted = cipher.encrypt(plaintext);
	const std::string decrypted = cipher.decrypt(encrypted);

	check(
		!encrypted.empty(),
		  "Playfair encryption");

	check(
		!decrypted.empty(),
		  "Playfair decryption");

	/*
	 * Playfair works on prepared alphabetic text.
	 * The C implementation normalizes J -> I and inserts padding.
	 */
	check(
		decrypted.find('J') == std::string::npos,
		  "Playfair decrypted text has no J");

	char enc_a = 0;
	char enc_b = 0;

	cipher.encrypt_pair(
		'H',
		'I',
		enc_a,
		enc_b);

	char dec_a = 0;
	char dec_b = 0;

	cipher.decrypt_pair(enc_a,enc_b,dec_a,dec_b);

	check(dec_a == 'H' && dec_b == 'I',"Playfair pair round trip");

	std::string padded = "HELXLOX";

	Playfair::remove_padding(padded);

	check(padded == "HELXLO","Playfair padding helper");

	/*
	 * In-place API expects already-prepared text.
	 */
	std::string prepared = "HIDETHEGOLDX";
	const std::string original = prepared;

	cipher.encrypt_inplace(prepared);
	check(prepared != original,"Playfair inplace encrypt");

	cipher.decrypt_inplace(prepared);
	check(prepared == original,"Playfair inplace round trip");
}

/*
 * CustomCipher test callback.
 *
 * This cipher simply XORs every byte with 0x5A.
 */
static int custom_encrypt(const void *data,std::size_t len,void **out,std::size_t *out_len) {
	if (!out || !out_len) return CUSTOMCIPHER_ERR_INVALID_ARG;
	*out = nullptr;
	*out_len = 0;
	if (!data && len != 0) return CUSTOMCIPHER_ERR_INVALID_ARG;
	if (len == 0) return CUSTOMCIPHER_SUCCESS;
	auto *result = static_cast<std::uint8_t *>(std::malloc(len));
	if (!result) return CUSTOMCIPHER_ERR_ALLOC_FAIL;
	const auto *input = static_cast<const std::uint8_t *>(data);
	for (std::size_t i = 0; i < len; ++i) result[i] = input[i] ^ 0x5A;
	*out = result;
	*out_len = len;
	return CUSTOMCIPHER_SUCCESS;
}

static int custom_decrypt(const void *data,std::size_t len,void **out,std::size_t *out_len) {
	/* XOR is its own inverse. */
	return custom_encrypt(data, len, out, out_len);
}

static void test_custom_cipher() {
	std::cout << "\n=== CustomCipher ===\n";

	hash::cipher::CustomCipher cipher(custom_encrypt,custom_decrypt);

	const std::string plaintext = "Hello Custom Cipher";

	const std::string encrypted = cipher.encrypt(plaintext);
	const std::string decrypted = cipher.decrypt(encrypted);

	check_equal(
		decrypted,
		plaintext,
		"CustomCipher string round trip");

	check(
		encrypted != plaintext,
	   "CustomCipher changes data");

	std::vector<std::uint8_t> input = {
		0x00,
		0x01,
		0x41,
		0x42,
		0x80,
		0xFF
	};

	auto encrypted_binary = cipher.encrypt(input);
	auto decrypted_binary = cipher.decrypt(encrypted_binary);

	check_equal(
		decrypted_binary,
		input,
		"CustomCipher binary round trip");

	check(
		cipher.native_handle() != nullptr,
		  "CustomCipher native handle");

	std::vector<std::uint8_t> empty;

	check(
		cipher.encrypt(empty).empty(),
		  "CustomCipher empty vector");

	check(
		cipher.decrypt(empty).empty(),
		  "CustomCipher empty decrypt");
}


int main() {
	try {
		std::cout << "cipher.hpp C++" LIBHASH_CXX_STANDARD " test suite\n";
		std::cout << "========================\n";
		test_caesar();
		test_vigenere();
		test_affine();
		test_atbash();
		test_playfair();
		test_custom_cipher();

		std::cout << "\n================================\n";
		std::cout << "Tests:  " << tests << '\n';
		std::cout << "Passed: " << passed << '\n';
		std::cout << "Failed: " << (tests - passed) << '\n';
		std::cout << "================================\n";

		return (tests == passed) ? EXIT_SUCCESS : EXIT_FAILURE;
	}
	catch (const std::exception& e) {
		std::cerr << "\nTest aborted: " << e.what() << '\n';
		std::cerr << "Passed: " << passed << "/" << tests << '\n';
		return EXIT_FAILURE;
	}
}
