/* Copyright (c) 2025 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include <kitcryptoc/sha2.h>
#include <stdlib.h>
#include <stdio.h>
#include "clock.h"

#define TEST_COUNT (1024)
#define TEST_SIZE (1024 * 1024)

uint64_t test_sha2_512(size_t len, uint8_t * data)
{
  uint8_t hash[KIT_SHA512_OUTPUT_SIZE_BYTES];

  kit_sha512(hash, data, len);
}

int main(int argc, char * argv[])
{
  uint8_t * block = malloc(TEST_SIZE);
  uint32_t * block4 = (uint32_t *)block;

  for (size_t i = 0; i < TEST_SIZE / 4; i++)
    block4[i] = rand();

  uint64_t sum = 0;
  for (size_t i = 0; i < TEST_COUNT; i++) {
    uint64_t t1 = getnow_monotonic();
    test_sha2_512(TEST_SIZE, block);
    uint64_t t2 = getnow_monotonic();
    sum += t2 - t1;
  }

  printf("%fs\n", (double)sum / (TEST_COUNT * 1000000000.0));

  return 0;
}
