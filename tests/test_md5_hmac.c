/* Copyright (c) 2024 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include <kitcryptoc/md5_hmac.h>
#include <stdio.h>
#include <string.h>

const uint8_t hash_md5_hmac_1[KIT_MD5_OUTPUT_SIZE_BYTES] = {
  0x80, 0x07, 0x07, 0x13, 0x46, 0x3e, 0x77, 0x49, 0xb9, 0x0c, 0x2d, 0xc2, 0x49,
  0x11, 0xe2, 0x75
};

int test_md5_hmac_1(void)
{
  uint8_t hash[KIT_MD5_OUTPUT_SIZE_BYTES];
  kit_md5_hmac(hash, "The quick brown fox jumps over the lazy dog", 43,
      "key", 3);
  int r = memcmp(hash, hash_md5_hmac_1, sizeof(hash_md5_hmac_1));
  if (r) {
    fprintf(stderr, "1. Invalid MD5-HMAC\n");
  }
  return 0;
}

int main(int argc, char * argv[])
{
  if (test_md5_hmac_1())
    return 1;

  return 0;
}
