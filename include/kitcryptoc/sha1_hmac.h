/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

#include "sha1.h"

typedef struct kit_sha1_hmac_ctx_s
{
  kit_sha1_ctx ctx;
  uint8_t int_key[KIT_SHA1_WORK_BLOCK_SIZE];
} kit_sha1_hmac_ctx;

void kit_sha1_hmac_init(kit_sha1_hmac_ctx * ctx, const uint8_t * key,
    size_t key_length);
void kit_sha1_hmac_append(kit_sha1_hmac_ctx * ctx, const uint8_t * data,
    size_t length);
void kit_sha1_hmac_finish(kit_sha1_hmac_ctx * ctx, uint8_t * output);

void kit_sha1_hmac(uint8_t * output, const uint8_t * input, size_t length,
    const uint8_t * key, size_t key_length);
