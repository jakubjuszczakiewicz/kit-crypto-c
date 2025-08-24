/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include <kitcryptoc/twofish.h>
#include <stdio.h>
#include "clock.h"

#define TEST_COUNT (1024 * 1024 * 10)

uint8_t key[32] = {
    0x7f, 0x7f, 0x6d, 0x6a, 0x23, 0x3a, 0x98, 0xd5, 0x49, 0x4b, 0x1b, 0x0e, 0xc0, 0x9f, 0x7f, 0x09,
    0xee, 0xc9, 0x2a, 0x48, 0x87, 0xe1, 0x49, 0x23, 0x8b, 0xf0, 0xa6, 0xb1, 0x17, 0xbb, 0xf4, 0xb4
};

uint8_t plaintext[2][16] = {
  { 0xe6, 0xd4, 0x7d, 0x6f, 0x02, 0xe6, 0xe4, 0x4a, 0x00, 0x0b, 0xd5, 0x5e, 0xf5, 0x52, 0xb2, 0x76 },
  { 0x03, 0xbf, 0x23, 0x94, 0xf8, 0x14, 0x0b, 0x45, 0x68, 0xa2, 0x08, 0x87, 0xd6, 0xf2, 0xcc, 0xb9 }
};

uint8_t encrypted_128[2][16] = {
  { 0x49, 0xeb, 0x29, 0xc0, 0xcb, 0x7d, 0xce, 0xb4, 0xc9, 0x38, 0x45, 0xfa, 0xe5, 0xb3, 0x5d, 0x6e },
  { 0x98, 0x1f, 0x98, 0xb8, 0x70, 0xa3, 0x65, 0xa4, 0x6a, 0x7b, 0xb5, 0x92, 0x86, 0xad, 0x47, 0x4e }
};

uint8_t encrypted_192[2][16] = {
  { 0x9a, 0xe9, 0x14, 0x8e, 0xbe, 0x37, 0x10, 0x1f, 0x73, 0xd3, 0x82, 0x34, 0x08, 0x7e, 0x2c, 0x21 },
  { 0xbe, 0x0c, 0xb2, 0x69, 0x98, 0x8e, 0x6b, 0x54, 0xfb, 0x9b, 0xc1, 0x14, 0x3e, 0xf7, 0xad, 0x0f }
};

uint8_t encrypted_256[2][16] = {
  { 0x47, 0xcc, 0x83, 0xcd, 0x25, 0x74, 0x00, 0xbc, 0xe9, 0x27, 0xd6, 0x8b, 0x87, 0xb0, 0xb0, 0x89 },
  { 0xe4, 0x3e, 0x5f, 0x4e, 0xd1, 0x21, 0xd5, 0x84, 0x1e, 0x7c, 0xff, 0x80, 0xbf, 0xc3, 0xb7, 0x71 }
};

uint64_t test_twofish_enc_128(unsigned int count)
{
  kit_twofish_key lkey;
  kit_twofish_init_128(&lkey, key);

  uint8_t output[16];

  uint64_t time1 = getnow_monotonic();

  for (unsigned int i = 0; i < count; i++)
    kit_twofish_encrypt_block(&lkey, output, plaintext[i & 1]);

  uint64_t time2 = getnow_monotonic();

  return time2 - time1;
}

uint64_t test_twofish_enc_192(unsigned int count)
{
  kit_twofish_key lkey;
  kit_twofish_init_192(&lkey, key);

  uint8_t output[16];

  uint64_t time1 = getnow_monotonic();

  for (unsigned int i = 0; i < count; i++)
    kit_twofish_encrypt_block(&lkey, output, plaintext[i & 1]);

  uint64_t time2 = getnow_monotonic();

  return time2 - time1;
}

uint64_t test_twofish_enc_256(unsigned int count)
{
  kit_twofish_key lkey;
  kit_twofish_init_256(&lkey, key);

  uint8_t output[16];

  uint64_t time1 = getnow_monotonic();

  for (unsigned int i = 0; i < count; i++)
    kit_twofish_encrypt_block(&lkey, output, plaintext[i & 1]);

  uint64_t time2 = getnow_monotonic();

  return time2 - time1;
}

uint64_t test_twofish_dec_128(unsigned int count)
{
  kit_twofish_key lkey;
  kit_twofish_init_128(&lkey, key);

  uint8_t output[16];

  uint64_t time1 = getnow_monotonic();

  for (unsigned int i = 0; i < count; i++)
    kit_twofish_decrypt_block(&lkey, output, encrypted_128[i & 1]);

  uint64_t time2 = getnow_monotonic();

  return time2 - time1;
}

uint64_t test_twofish_dec_192(unsigned int count)
{
  kit_twofish_key lkey;
  kit_twofish_init_192(&lkey, key);

  uint8_t output[16];

  uint64_t time1 = getnow_monotonic();

  for (unsigned int i = 0; i < count; i++)
    kit_twofish_decrypt_block(&lkey, output, encrypted_192[i & 1]);

  uint64_t time2 = getnow_monotonic();

  return time2 - time1;
}

uint64_t test_twofish_dec_256(unsigned int count)
{
  kit_twofish_key lkey;
  kit_twofish_init_256(&lkey, key);

  uint8_t output[16];

  uint64_t time1 = getnow_monotonic();

  for (unsigned int i = 0; i < count; i++)
    kit_twofish_decrypt_block(&lkey, output, encrypted_256[i & 1]);

  uint64_t time2 = getnow_monotonic();

  return time2 - time1;
}

int main(int argc, char * argv[])
{
  uint64_t enc128 = test_twofish_enc_128(TEST_COUNT);
  uint64_t enc192 = test_twofish_enc_192(TEST_COUNT);
  uint64_t enc256 = test_twofish_enc_256(TEST_COUNT);
  uint64_t dec128 = test_twofish_dec_128(TEST_COUNT);
  uint64_t dec192 = test_twofish_dec_192(TEST_COUNT);
  uint64_t dec256 = test_twofish_dec_256(TEST_COUNT);

  printf("Encrypt Twofish 128 time: %f sec\n", (double)enc128 / 1000000000.0);
  printf("Encrypt Twofish 192 time: %f sec\n", (double)enc192 / 1000000000.0);
  printf("Encrypt Twofish 256 time: %f sec\n", (double)enc256 / 1000000000.0);

  printf("Decrypt Twofish 128 time: %f sec\n", (double)dec128 / 1000000000.0);
  printf("Decrypt Twofish 192 time: %f sec\n", (double)dec192 / 1000000000.0);
  printf("Decrypt Twofish 256 time: %f sec\n", (double)dec256 / 1000000000.0);

  return 0;
}
