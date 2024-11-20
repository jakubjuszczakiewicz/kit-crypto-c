# Copyright (c) 2024 Krypto-IT Jakub Juszczakiewicz
# All rights reserved.

cmake_minimum_required(VERSION 3.1...3.5)
project(kit-crypto-c C)

set(WITH_TESTS TRUE CACHE BOOL true)

include_directories(
  include
)

set(HEADER_FILES include/kitcryptoc/version.h)
set(SOURCE_FILES src/version.c)

include (TestBigEndian)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
 add_definitions(-DBIG_ENDIAN)
else()
 add_definitions(-DLITTLE_ENDIAN)
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  add_definitions(-DSIZE_T_BITS=64)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
  add_definitions(-DSIZE_T_BITS=32)
else()
  message(FATAL_ERROR "Unsupported architecture")
endif()

set(ALG_NASM False CACHE BOOL "Add support for assembler code compiled by nasm")
if (ALG_NASM)
  enable_language(ASM_NASM)
endif()

set(ASM False CACHE BOOL "Use assembler code")

if (ASM)
set(CPUNAME "" CACHE STRING "CPU name")
endif()

set(ALG_AES True CACHE BOOL "Add support for AES algorithm")
if (ALG_AES)
  add_definitions(-DALG_AES)
  list(APPEND HEADER_FILES include/kitcryptoc/aes.h)
  list(APPEND SOURCE_FILES src/aes.c)

  set(ALG_AES_NI False CACHE BOOL "Add support for AES-NI implementation")
  if (ALG_AES_NI AND ASM)
    add_definitions(-DALG_AES_NI)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
      list(APPEND SOURCE_FILES src/x86-64/aesni_unix.asm)
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
      list(APPEND SOURCE_FILES src/i386/aesni_unix.asm)
    endif()
  endif()

  set(ALG_AES_AARCH64 False CACHE BOOL "Add support for AArch64 AES implementation")
  if (ALG_AES_AARCH64 AND ASM AND CPUNAME)
    add_definitions(-DALG_AES_AARCH64)
    list(APPEND SOURCE_FILES src/aarch64/aes_unix.S)
    set(CMAKE_ASM_FLAGS "-x assembler-with-cpp -mcpu=${CPUNAME} -c" CACHE STRING "" FORCE)
  endif()

  set(ALG_AES_AARCH32 False CACHE BOOL "Add support for AArch64 AES implementation in 32bit mode")
  if (ALG_AES_AARCH32 AND ASM AND CPUNAME)
    add_definitions(-DALG_AES_AARCH32)
    list(APPEND SOURCE_FILES src/aarch32/aes_unix.S)
    set(CMAKE_ASM_FLAGS "-x assembler-with-cpp -mcpu=${CPUNAME} -mfpu=crypto-neon-fp-armv8 -c" CACHE STRING "" FORCE)
  endif()
endif()

set(ALG_TWOFISH True CACHE BOOL "Add support for Twofish algorithm")
if (ALG_TWOFISH)
  add_definitions(-DALG_TWOFISH)
  list(APPEND HEADER_FILES include/kitcryptoc/twofish.h)
  list(APPEND SOURCE_FILES src/twofish.c)
endif()

set(ALG_SHA2 True CACHE BOOL "Add support for SHA2 algorithms")
if (ALG_SHA2)
  add_definitions(-DALG_SHA2)
  list(APPEND HEADER_FILES include/kitcryptoc/sha2.h include/kitcryptoc/sha2_hmac.h)
  list(APPEND SOURCE_FILES src/sha2.c src/sha2_hmac.c)
endif()

set(ALG_MD5 True CACHE BOOL "Add support for MD5 algorithms")
if (ALG_MD5)
  add_definitions(-DALG_MD5)
  list(APPEND HEADER_FILES include/kitcryptoc/md5.h include/kitcryptoc/md5_hmac.h)
  list(APPEND SOURCE_FILES src/md5.c src/md5_hmac.c)
endif()

set(ALG_SHA1 True CACHE BOOL "Add support for SHA1 algorithms")
if (ALG_SHA1)
  add_definitions(-DALG_SHA1)
  list(APPEND HEADER_FILES include/kitcryptoc/sha1.h include/kitcryptoc/sha1_hmac.h)
  list(APPEND SOURCE_FILES src/sha1.c src/sha1_hmac.c)
endif()

set(BUILD_STATIC True CACHE BOOL "Build static library")
set(BUILD_SHARED True CACHE BOOL "Build shared library")

if (BUILD_STATIC)
if (NOT BUILD_SHARED)
add_library(kitcryptoc_static STATIC ${SOURCE_FILES})
endif()
endif()

if (BUILD_SHARED)
if (BUILD_STATIC)
add_library(kitcryptoc_obj OBJECT ${SOURCE_FILES})
set_property(TARGET kitcryptoc_obj PROPERTY POSITION_INDEPENDENT_CODE 1)
add_library(kitcryptoc SHARED $<TARGET_OBJECTS:kitcryptoc_obj>)
add_library(kitcryptoc_static STATIC $<TARGET_OBJECTS:kitcryptoc_obj>)
install(TARGETS kitcryptoc_static LIBRARY DESTINATION lib)
else()
add_library(kitcryptoc SHARED ${SOURCE_FILES})
endif()
install(TARGETS kitcryptoc LIBRARY DESTINATION lib)
endif()

install(FILES ${HEADER_FILES} DESTINATION include/kitcryptoc)

if (${WITH_TESTS})
  include(CTest)
  add_subdirectory(tests)
endif()
