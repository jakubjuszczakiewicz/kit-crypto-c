/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include <kitcryptoc/version.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
  if (strlen(kit_crypto_c_version_str) != kit_crypto_c_version_str_len) {
    fprintf(stderr, "Invalid version string length");
    return 1;
  }

  return 0;
}
