/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#define KIT_SHA1_OUTPUT_SIZE_BYTES 20

#define KIT_SHA1_WORK_BLOCK_SIZE 64

#define KIT_SHA1_STATE_VALUES_COUNT 5

typedef struct kit_sha1_ctx_s
{
  uint64_t processed_bytes;
  uint32_t h[KIT_SHA1_STATE_VALUES_COUNT];
  uint8_t buf[KIT_SHA1_WORK_BLOCK_SIZE];
  uint32_t buf_fill;
} kit_sha1_ctx;

void kit_sha1_init(kit_sha1_ctx * ctx);
void kit_sha1_append(kit_sha1_ctx * ctx, const uint8_t * data, size_t length);
void kit_sha1_finish(kit_sha1_ctx * ctx, uint8_t * output);

void kit_sha1(uint8_t * output, const uint8_t * input, size_t length);
