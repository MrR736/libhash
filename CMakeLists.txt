cmake_minimum_required(VERSION 3.20)
project(libhash VERSION 1.0.0 LANGUAGES C)

# --------------------------------------------------
# General build settings
# --------------------------------------------------
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BUILD_WINDOWS "Enable Windows library build" OFF)
option(BUILD_TESTS "Build all test executables" ON)

# Output directories
set(OUTPUT_DIR "${CMAKE_BINARY_DIR}/build/${CMAKE_SYSTEM_PROCESSOR}")
set(LIBS_OUTPUT_DIR "${OUTPUT_DIR}/lib")
set(TEST_DIR "${OUTPUT_DIR}/test")

file(MAKE_DIRECTORY "${LIBS_OUTPUT_DIR}" "${TEST_DIR}")

# --------------------------------------------------
# Windows / MinGW support
# --------------------------------------------------
if(BUILD_WINDOWS OR WIN32)
    list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
    include(CMakeWindowsMingw32-C)
endif()

# --------------------------------------------------
# Library target
# --------------------------------------------------
add_library(${PROJECT_NAME} SHARED ${CMAKE_SOURCE_DIR}/src/hash.c)
target_include_directories(${PROJECT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/src")

set_target_properties(${PROJECT_NAME} PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${LIBS_OUTPUT_DIR}
    LIBRARY_OUTPUT_DIRECTORY ${LIBS_OUTPUT_DIR}
    RUNTIME_OUTPUT_DIRECTORY ${LIBS_OUTPUT_DIR}
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

if(BUILD_WINDOWS OR WIN32)
    # MinGW-specific linker option (optional)
    if(MINGW)
        target_link_options(${PROJECT_NAME} PRIVATE
            "LINKER:--output-def=${LIBS_OUTPUT_DIR}/hash.def"
        )
    endif()
endif()

# --------------------------------------------------
# Helper function for adding tests
# --------------------------------------------------
function(add_test_executable target_name)
    add_executable(${target_name} ${ARGN})
    target_include_directories(${target_name} PRIVATE "${CMAKE_SOURCE_DIR}/include/hash")
    target_link_libraries(${target_name} PRIVATE ${PROJECT_NAME})
    set_target_properties(${target_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${TEST_DIR}
    )
    add_test(NAME ${target_name} COMMAND ${TEST_DIR}/${target_name})
endfunction()

# --------------------------------------------------
# Add tests if enabled
# --------------------------------------------------
if(BUILD_TESTS)
    add_test_executable(aes-test ${CMAKE_SOURCE_DIR}/test/test_aes.c)
    add_test_executable(aescbc-test ${CMAKE_SOURCE_DIR}/test/test_aescbc.c)
    add_test_executable(aesctr-test ${CMAKE_SOURCE_DIR}/test/test_aesctr.c)
    add_test_executable(aesofb-test ${CMAKE_SOURCE_DIR}/test/test_aesofb.c)
    add_test_executable(crc32-test ${CMAKE_SOURCE_DIR}/test/test_crc32.c)
    add_test_executable(md2-test ${CMAKE_SOURCE_DIR}/test/test_md2.c)
    add_test_executable(md4-test ${CMAKE_SOURCE_DIR}/test/test_md4.c)
    add_test_executable(md5-test ${CMAKE_SOURCE_DIR}/test/test_md5.c)
    add_test_executable(rc4-test ${CMAKE_SOURCE_DIR}/test/test_rc4.c)
    add_test_executable(sha1-test ${CMAKE_SOURCE_DIR}/test/test_sha1.c)
    add_test_executable(sha224-test ${CMAKE_SOURCE_DIR}/test/test_sha224.c)
    add_test_executable(sha256-test ${CMAKE_SOURCE_DIR}/test/test_sha256.c)
    add_test_executable(sha384-test ${CMAKE_SOURCE_DIR}/test/test_sha384.c)
    add_test_executable(sha512-test ${CMAKE_SOURCE_DIR}/test/test_sha512.c)
    add_test_executable(base16-test ${CMAKE_SOURCE_DIR}/test/test_base16.c)
    add_test_executable(base32-test ${CMAKE_SOURCE_DIR}/test/test_base32.c)
    add_test_executable(base64-test ${CMAKE_SOURCE_DIR}/test/test_base64.c)

    enable_testing()
endif()

# --------------------------------------------------
# Installation rules (Linux/macOS)
# --------------------------------------------------
if(NOT BUILD_WINDOWS AND NOT WIN32)
    install(TARGETS ${PROJECT_NAME}
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin
    )

    install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/hash/
        DESTINATION include/hash
        FILES_MATCHING PATTERN "*.h"
    )
endif()
