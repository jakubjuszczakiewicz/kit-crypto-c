# Copyright (c) 2024 Krypto-IT Jakub Juszczakiewicz
# All rights reserved.

enable_testing()

if (ALG_AES)
list(APPEND TESTS aes)
list(APPEND PERF_TESTS aes)
endif()

if (ALG_TWOFISH)
list(APPEND TESTS twofish)
list(APPEND PERF_TESTS twofish)
endif()

if (ALG_SHA2)
list(APPEND TESTS sha2)
list(APPEND TESTS sha2_hmac)
endif()

if (ALG_MD5)
list(APPEND TESTS md5 md5_hmac)
endif()

if (ALG_SHA1)
list(APPEND TESTS sha1)
list(APPEND TESTS sha1_hmac)
endif()


if (BUILD_SHARED)
  set(TESTLIB kitcryptoc)
elseif (BUILD_STATIC)
  set(TESTLIB kitcryptoc_static)
else()
  message(FATAL_ERROR "Can't build test without lib")
endif()

foreach(TEST ${TESTS})
  add_executable(${TEST} "test_${TEST}.c")
  target_link_libraries(${TEST} ${TESTLIB})
  add_test(NAME ${TEST} COMMAND ${TEST})
endforeach()

foreach(TEST ${PERF_TESTS})
  add_executable(perf_${TEST} "test_perf_${TEST}.c" "clock.c")
  target_link_libraries(perf_${TEST} ${TESTLIB})
endforeach()
