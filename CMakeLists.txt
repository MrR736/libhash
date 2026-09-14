cmake_minimum_required(VERSION 3.20)
project(libhash VERSION 1.0.1 LANGUAGES C CXX)

# General build settings
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 11)

option(LIBHASH_TESTS "Build all test executables" ON)
option(LIBHASH_EMBEDDED "Enable Build Embedded" OFF)
option(LIBHASH_USE_FILE "Enable FILE type" ON)
option(LIBHASH_USE_FD "Use file descriptors instead of FILE" OFF)

# Library target
add_library(hash SHARED ${CMAKE_SOURCE_DIR}/src/hash.c)
target_include_directories(hash PRIVATE "${CMAKE_SOURCE_DIR}/src")

set_target_properties(hash PROPERTIES
	OUTPUT_NAME "hash"
)

if(WIN32)
	set_target_properties(hash PROPERTIES
		PREFIX ""
		ARCHIVE_OUTPUT_NAME "hash"
	)
	if(MINGW)
		target_link_options(hash PRIVATE "LINKER:--output-def=${CMAKE_CURRENT_BINARY_DIR}/hash.def")
	endif()
else()
	set_target_properties(hash PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})
endif()

if(LIBHASH_EMBEDDED)
	target_compile_definitions(hash PUBLIC HASH_USE_CUSTOM_MEM=1)
else()
	if(LIBHASH_USE_FILE)
		target_compile_definitions(hash PUBLIC LIBHASH_USE_FILE)
		if (LIBHASH_USE_FD)
			target_compile_definitions(hash PUBLIC LIBHASH_USE_FD)
		endif()
	endif()
endif()


target_compile_options(hash PRIVATE -O0)

# Installation rules (Linux/macOS)
if(NOT WIN32)
	install(TARGETS hash
		ARCHIVE DESTINATION lib
		LIBRARY DESTINATION lib
		RUNTIME DESTINATION bin
	)
	install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/hash/ DESTINATION include/hash FILES_MATCHING PATTERN "*.h")
endif()

# Helper function for adding tests
if(WIN32)
	find_program(WINE_EXECUTABLE NAMES wine wine64)
endif()

function(add_test_executable target_name)
	add_executable(${target_name} ${ARGN})
	target_include_directories(${target_name} PRIVATE "${CMAKE_SOURCE_DIR}/include/hash" "${CMAKE_SOURCE_DIR}/include/hash/cipher")
	target_link_libraries(${target_name} PRIVATE hash)
	target_compile_definitions(${target_name} PUBLIC LIBHASH_CXX_STANDARD="${CMAKE_CXX_STANDARD}")
	if(WINE_EXECUTABLE)
		add_test(NAME ${target_name} COMMAND ${WINE_EXECUTABLE} $<TARGET_FILE:${target_name}>)
	else()
		add_test(NAME ${target_name} COMMAND $<TARGET_FILE:${target_name}>)
	endif()
endfunction()

# Add tests if enabled
if(LIBHASH_TESTS)
	enable_testing()
	add_test_executable(aes-test ${CMAKE_SOURCE_DIR}/test/test_aes.c)
	add_test_executable(aescbc-test ${CMAKE_SOURCE_DIR}/test/test_aescbc.c)
	add_test_executable(aesctr-test ${CMAKE_SOURCE_DIR}/test/test_aesctr.c)
	add_test_executable(aesofb-test ${CMAKE_SOURCE_DIR}/test/test_aesofb.c)
	add_test_executable(crc8-test ${CMAKE_SOURCE_DIR}/test/test_crc8.c)
	add_test_executable(crc16-test ${CMAKE_SOURCE_DIR}/test/test_crc16.c)
	add_test_executable(crc32-test ${CMAKE_SOURCE_DIR}/test/test_crc32.c)
	add_test_executable(crc64-test ${CMAKE_SOURCE_DIR}/test/test_crc64.c)
	add_test_executable(md2-test ${CMAKE_SOURCE_DIR}/test/test_md2.c)
	add_test_executable(md4-test ${CMAKE_SOURCE_DIR}/test/test_md4.c)
	add_test_executable(md5-test ${CMAKE_SOURCE_DIR}/test/test_md5.c)
	add_test_executable(rc4-test ${CMAKE_SOURCE_DIR}/test/test_rc4.c)
	add_test_executable(sha0-test ${CMAKE_SOURCE_DIR}/test/test_sha0.c)
	add_test_executable(sha1-test ${CMAKE_SOURCE_DIR}/test/test_sha1.c)
	add_test_executable(sha224-test ${CMAKE_SOURCE_DIR}/test/test_sha224.c)
	add_test_executable(sha256-test ${CMAKE_SOURCE_DIR}/test/test_sha256.c)
	add_test_executable(sha384-test ${CMAKE_SOURCE_DIR}/test/test_sha384.c)
	add_test_executable(sha512-test ${CMAKE_SOURCE_DIR}/test/test_sha512.c)
	add_test_executable(sha3-256-test ${CMAKE_SOURCE_DIR}/test/test_sha3-256.c)
	add_test_executable(sha3-512-test ${CMAKE_SOURCE_DIR}/test/test_sha3-512.c)
	add_test_executable(sha512-224-test ${CMAKE_SOURCE_DIR}/test/test_sha512-224.c)
	add_test_executable(sha512-256-test ${CMAKE_SOURCE_DIR}/test/test_sha512-256.c)
	add_test_executable(base16-test ${CMAKE_SOURCE_DIR}/test/test_base16.c)
	add_test_executable(base32-test ${CMAKE_SOURCE_DIR}/test/test_base32.c)
	add_test_executable(base58-test ${CMAKE_SOURCE_DIR}/test/test_base58.c)
	add_test_executable(base64-test ${CMAKE_SOURCE_DIR}/test/test_base64.c)

	add_test_executable(affine-test ${CMAKE_SOURCE_DIR}/test/test_affine.c)
	add_test_executable(atbash-test ${CMAKE_SOURCE_DIR}/test/test_atbash.c)
	add_test_executable(caesar-test ${CMAKE_SOURCE_DIR}/test/test_caesar.c)
	add_test_executable(playfair-test ${CMAKE_SOURCE_DIR}/test/test_playfair.c)
	add_test_executable(vigenere-test ${CMAKE_SOURCE_DIR}/test/test_vigenere.c)
	add_test_executable(customcipher-test ${CMAKE_SOURCE_DIR}/test/test_customcipher.c)

	add_test_executable(hash-test ${CMAKE_SOURCE_DIR}/test/test_hash.c)

	add_test_executable(cipher-test ${CMAKE_SOURCE_DIR}/test/test_cipher.cpp)
	add_test_executable(hash-cpp-test ${CMAKE_SOURCE_DIR}/test/test_hash.cpp)
endif()
