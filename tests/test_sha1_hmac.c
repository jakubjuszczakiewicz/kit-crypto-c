/* Copyright (c) 2024 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include <kitcryptoc/sha1_hmac.h>
#include <stdio.h>
#include <string.h>

const uint8_t hash_sha1_hmac_1[KIT_SHA1_OUTPUT_SIZE_BYTES] = {
  0xde, 0x7c, 0x9b, 0x85, 0xb8, 0xb7, 0x8a, 0xa6, 0xbc, 0x8a, 0x7a, 0x36, 0xf7,
  0x0a, 0x90, 0x70, 0x1c, 0x9d, 0xb4, 0xd9
};

int test_sha1_hmac_1(void)
{
  uint8_t hash[KIT_SHA1_OUTPUT_SIZE_BYTES];
  kit_sha1_hmac(hash, "The quick brown fox jumps over the lazy dog", 43,
      "key", 3);
  int r = memcmp(hash, hash_sha1_hmac_1, sizeof(hash_sha1_hmac_1));
  if (r) {
    fprintf(stderr, "1. Invalid SHA1-HMAC\n");
  }
  return 0;
}

int main(int argc, char * argv[])
{
  if (test_sha1_hmac_1())
    return 1;

  return 0;
}
