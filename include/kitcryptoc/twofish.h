/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#define KIT_TWOFISH_INT_KEY_SIZE 60

typedef struct kit_twofish_key_s
{
  unsigned int keySize;
  uint32_t key[8];
  uint32_t sbox_key[4];
  uint32_t sub_key[40];
  void (*e)(const struct kit_twofish_key_s * key, uint8_t * output,
      const uint8_t * input);
  void (*d)(const struct kit_twofish_key_s * key, uint8_t * output,
      const uint8_t * input);
} kit_twofish_key;

void kit_twofish_init_128(kit_twofish_key * key, const uint8_t * source);
void kit_twofish_init_192(kit_twofish_key * key, const uint8_t * source);
void kit_twofish_init_256(kit_twofish_key * key, const uint8_t * source);

void kit_twofish_encrypt_block(const kit_twofish_key * key, uint8_t * output,
    const uint8_t * input);
void kit_twofish_decrypt_block(const kit_twofish_key * key, uint8_t * output,
    const uint8_t * input);
