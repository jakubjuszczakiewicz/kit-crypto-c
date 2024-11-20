/* Copyright (c) 2024 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#define KIT_MD5_OUTPUT_SIZE_BYTES 16

#define KIT_MD5_WORK_BLOCK_SIZE 64

#define KIT_MD5_STATE_VALUES_COUNT 4

typedef struct kit_md5_ctx_s
{
  uint64_t processed_bytes;
  uint32_t h[KIT_MD5_STATE_VALUES_COUNT];
  uint8_t buf[KIT_MD5_WORK_BLOCK_SIZE];
  uint32_t buf_fill;
} kit_md5_ctx;

void kit_md5_init(kit_md5_ctx * ctx);
void kit_md5_append(kit_md5_ctx * ctx, const uint8_t * data, size_t length);
void kit_md5_finish(kit_md5_ctx * ctx, uint8_t * output);

void kit_md5(uint8_t * output, const uint8_t * input, size_t length);
