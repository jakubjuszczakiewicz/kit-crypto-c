/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

#include <stdint.h>

#define KIT_AES_INT_KEY_SIZE 104

typedef struct kit_aes_key_s
{
  uint32_t key[KIT_AES_INT_KEY_SIZE];
  uint8_t rounds;
  void (*e)(const struct kit_aes_key_s * key, uint8_t * output,
      const uint8_t * input);
  void (*d)(const struct kit_aes_key_s * key, uint8_t * output,
      const uint8_t * input);
} kit_aes_key;

void kit_aes_init_128(kit_aes_key * key, const uint8_t * source);
void kit_aes_init_192(kit_aes_key * key, const uint8_t * source);
void kit_aes_init_256(kit_aes_key * key, const uint8_t * source);

void kit_aes_encrypt_block(const kit_aes_key * key, uint8_t * output,
    const uint8_t * input);
void kit_aes_decrypt_block(const kit_aes_key * key, uint8_t * output,
    const uint8_t * input);
