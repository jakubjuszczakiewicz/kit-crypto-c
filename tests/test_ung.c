/* Copyright (c) 2025 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include <kitcryptoc/ung.h>
#include <stdio.h>
#include <string.h>
#include <kitcryptoc/sha2.h>

int test_ung_256(void)
{
  uint8_t init[32], out[30];
  memset(init, 0x78, 32);

  struct kit_ung_256 ctx;
  kit_ung_256_init(&ctx, kit_sha256, init);

  kit_ung_256_next(&ctx, out, 30);

  kit_ung_256_finish(&ctx);

  return !memcmp(init, out, 30);
}

int test_ung_512(void)
{
  uint8_t init[64], out[61];
  memset(init, 0x78, 64);

  struct kit_ung_512 ctx;
  kit_ung_512_init(&ctx, kit_sha512, init);

  kit_ung_512_next(&ctx, out, 30);

  kit_ung_512_finish(&ctx);

  return !memcmp(init, out, 30);
}

int main(int argc, char * argv[])
{
  if (test_ung_256())
    return 1;
  if (test_ung_512())
    return 1;

  return 0;
}
