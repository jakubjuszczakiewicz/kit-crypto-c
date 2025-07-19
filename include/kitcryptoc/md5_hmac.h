/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

#include "md5.h"

typedef struct kit_md5_hmac_ctx_s
{
  kit_md5_ctx ctx;
  uint8_t int_key[KIT_MD5_WORK_BLOCK_SIZE];
} kit_md5_hmac_ctx;

void kit_md5_hmac_init(kit_md5_hmac_ctx * ctx, const uint8_t * key,
    size_t key_length);
void kit_md5_hmac_append(kit_md5_hmac_ctx * ctx, const uint8_t * data,
    size_t length);
void kit_md5_hmac_finish(kit_md5_hmac_ctx * ctx, uint8_t * output);

void kit_md5_hmac(uint8_t * output, const uint8_t * input, size_t length,
    const uint8_t * key, size_t key_length);
