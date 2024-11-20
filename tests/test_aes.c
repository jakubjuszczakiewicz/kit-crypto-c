/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include <kitcryptoc/aes.h>
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
  { 0xbf, 0xb5, 0xeb, 0x53, 0xbc, 0xf8, 0xec, 0x0f, 0x82, 0xb8, 0x6a, 0xfe, 0x41, 0xb1, 0x7a, 0x6a },
  { 0x40, 0x25, 0xf4, 0x6f, 0xce, 0x69, 0xfc, 0x7d, 0x95, 0xcf, 0xef, 0x48, 0x85, 0xe6, 0x64, 0x83 }
};

uint8_t encrypted_192[2][16] = {
  { 0x65, 0xaf, 0xa4, 0x12, 0x1f, 0x6c, 0xe9, 0x5b, 0xec, 0x0c, 0x66, 0x96, 0x0c, 0x66, 0xa2, 0xef },
  { 0x4c, 0x04, 0xdf, 0x80, 0xab, 0x4c, 0xd3, 0x9c, 0x70, 0x1d, 0xbd, 0x8c, 0xb1, 0x1e, 0x69, 0x43 }
};

uint8_t encrypted_256[2][16] = {
  { 0x3c, 0x6d, 0x7c, 0xa9, 0x1e, 0xb6, 0xe2, 0x57, 0x21, 0x00, 0x39, 0x91, 0x2c, 0x15, 0xc5, 0x39 },
  { 0xa2, 0xe8, 0x71, 0xd9, 0x74, 0x28, 0x49, 0xfb, 0x8d, 0xd8, 0xbf, 0x34, 0x23, 0xe0, 0x06, 0xef }
};

int test_aes128(void)
{
  kit_aes_key lkey;
  kit_aes_init_128(&lkey, key);

  uint8_t output[16], output2[16];

  kit_aes_encrypt_block(&lkey, output, plaintext[0]);
  if (memcmp(output, encrypted_128[0], 16)) {
    fprintf(stderr, "AES 128 encryption fail (1)\n");
    return 1;
  }

  kit_aes_decrypt_block(&lkey, output2, output);
  if (memcmp(output2, plaintext[0], 16)) {
    fprintf(stderr, "AES 128 decryption fail (1)\n");
    return 1;
  }

  kit_aes_encrypt_block(&lkey, output, plaintext[1]);
  if (memcmp(output, encrypted_128[1], 16)) {
    fprintf(stderr, "AES 128 encryption fail (2)\n");
    return 1;
  }

  kit_aes_decrypt_block(&lkey, output2, output);
  if (memcmp(output2, plaintext[1], 16)) {
    fprintf(stderr, "AES 128 decryption fail (2)\n");
    return 1;
  }

  return 0;
}

int test_aes192(void)
{
  kit_aes_key lkey;
  kit_aes_init_192(&lkey, key);

  uint8_t output[16], output2[16];

  kit_aes_encrypt_block(&lkey, output, plaintext[0]);
  if (memcmp(output, encrypted_192[0], 16)) {
    fprintf(stderr, "AES 192 encryption fail (1)\n");    
    return 1;
  }

  kit_aes_decrypt_block(&lkey, output2, output);
  if (memcmp(output2, plaintext[0], 16)) {
    fprintf(stderr, "AES 192 decryption fail (1)\n");
    return 1;
  }

  kit_aes_encrypt_block(&lkey, output, plaintext[1]);
  if (memcmp(output, encrypted_192[1], 16)) {
    fprintf(stderr, "AES 192 encryption fail (2)\n");
    return 1;
  }

  kit_aes_decrypt_block(&lkey, output2, output);
  if (memcmp(output2, plaintext[1], 16)) {
    fprintf(stderr, "AES 192 decryption fail (2)\n");
    return 1;
  }

  return 0;
}

int test_aes256(void)
{
  kit_aes_key lkey;
  kit_aes_init_256(&lkey, key);

  uint8_t output[16], output2[16];

  kit_aes_encrypt_block(&lkey, output, plaintext[0]);
  if (memcmp(output, encrypted_256[0], 16)) {
    fprintf(stderr, "AES 256 encryption fail (1)\n");    
    return 1;
  }

  kit_aes_decrypt_block(&lkey, output2, output);
  if (memcmp(output2, plaintext[0], 16)) {
    fprintf(stderr, "AES 256 decryption fail (1)\n");
    return 1;
  }

  kit_aes_encrypt_block(&lkey, output, plaintext[1]);
  if (memcmp(output, encrypted_256[1], 16)) {
    fprintf(stderr, "AES 256 encryption fail (2)\n");
    return 1;
  }

  kit_aes_decrypt_block(&lkey, output2, output);
  if (memcmp(output2, plaintext[1], 16)) {
    fprintf(stderr, "AES 256 decryption fail (2)\n");
    return 1;
  }

  return 0;
}

int main(int argc, char * argv[])
{
  if (test_aes128())
    return 1;
  if (test_aes192())
    return 1;
  if (test_aes256())
    return 1;

  return 0;
}
