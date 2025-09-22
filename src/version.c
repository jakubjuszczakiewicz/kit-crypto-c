/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include <kitcryptoc/version.h>
#include <string.h>

#define VERSION_MAJOR 0
#define VERSION_MINOR 0
#define VERSION_PATCH 12
#define VERSION_SUBSTR ""

#define STR(s) #s
#define MAKE_VER(ma, mi, pa, st) (STR(ma) "." STR(mi) "." STR(pa) st)

#define VERSION_STR MAKE_VER(VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, VERSION_SUBSTR)

uint16_t kit_crypto_c_version[3] = { VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH };

const char kit_crypto_c_version_str[] = VERSION_STR;
#if (!defined(USE_WINAPI)) || defined(IS_MINGW)
size_t kit_crypto_c_version_str_len = strlen(VERSION_STR);
#else
size_t kit_crypto_c_version_str_len = sizeof(kit_crypto_c_version_str) - 1;
#endif
