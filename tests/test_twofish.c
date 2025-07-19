/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include <kitcryptoc/twofish.h>

#include <stdio.h>
#include <string.h>

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

int test_twofish128(void)
{
  kit_twofish_key lkey;
  kit_twofish_init_128(&lkey, key);

  uint8_t output[18], output2[16];

  kit_twofish_encrypt_block(&lkey, output, plaintext[0]);
  if (memcmp(output, encrypted_128[0], 16)) {
    fprintf(stderr, "Twofish 128 encryption fail (1)\n");
    return 1;
  }

  kit_twofish_decrypt_block(&lkey, output2, output);
  if (memcmp(output2, plaintext[0], 16)) {
    fprintf(stderr, "Twofish 128 decryption fail (1)\n");
    return 1;
  }

  kit_twofish_encrypt_block(&lkey, output, plaintext[1]);
  if (memcmp(output, encrypted_128[1], 16)) {
    fprintf(stderr, "Twofish 128 encryption fail (2)\n");
    return 1;
  }

  kit_twofish_decrypt_block(&lkey, output2, output);
  if (memcmp(output2, plaintext[1], 16)) {
    fprintf(stderr, "Twofish 128 decryption fail (2)\n");
    return 1;
  }

  kit_twofish_encrypt_block(&lkey, output + 2, plaintext[0]);
  if (memcmp(output + 2, encrypted_128[0], 16)) {
    fprintf(stderr, "Twofish 128 encryption fail (3)\n");
    return 1;
  }

  return 0;
}

int test_twofish192(void)
{
  kit_twofish_key lkey;
  kit_twofish_init_192(&lkey, key);

  uint8_t output[16], output2[16];

  kit_twofish_encrypt_block(&lkey, output, plaintext[0]);
  if (memcmp(output, encrypted_192[0], 16)) {
    fprintf(stderr, "Twofish 192 encryption fail (1)\n");    
    return 1;
  }

  kit_twofish_decrypt_block(&lkey, output2, output);
  if (memcmp(output2, plaintext[0], 16)) {
    fprintf(stderr, "Twofish 192 decryption fail (1)\n");
    return 1;
  }

  kit_twofish_encrypt_block(&lkey, output, plaintext[1]);
  if (memcmp(output, encrypted_192[1], 16)) {
    fprintf(stderr, "Twofish 192 encryption fail (2)\n");
    return 1;
  }

  kit_twofish_decrypt_block(&lkey, output2, output);
  if (memcmp(output2, plaintext[1], 16)) {
    fprintf(stderr, "Twofish 192 decryption fail (2)\n");
    return 1;
  }

  return 0;
}

int test_twofish256(void)
{
  kit_twofish_key lkey;
  kit_twofish_init_256(&lkey, key);

  uint8_t output[16], output2[16];

  kit_twofish_encrypt_block(&lkey, output, plaintext[0]);
  if (memcmp(output, encrypted_256[0], 16)) {
    fprintf(stderr, "Twofish 256 encryption fail (1)\n");    
    return 1;
  }

  kit_twofish_decrypt_block(&lkey, output2, output);
  if (memcmp(output2, plaintext[0], 16)) {
    fprintf(stderr, "Twofish 256 decryption fail (1)\n");
    return 1;
  }

  kit_twofish_encrypt_block(&lkey, output, plaintext[1]);
  if (memcmp(output, encrypted_256[1], 16)) {
    fprintf(stderr, "Twofish 256 encryption fail (2)\n");
    return 1;
  }

  kit_twofish_decrypt_block(&lkey, output2, output);
  if (memcmp(output2, plaintext[1], 16)) {
    fprintf(stderr, "Twofish 256 decryption fail (2)\n");
    return 1;
  }

  return 0;
}

int main(int argc, char * argv[])
{
  if (test_twofish128())
    return 1;
  if (test_twofish192())
    return 1;
  if (test_twofish256())
    return 1;

  return 0;
}
