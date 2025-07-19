/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#define KIT_SHA224_OUTPUT_SIZE_BYTES 28
#define KIT_SHA256_OUTPUT_SIZE_BYTES 32
#define KIT_SHA384_OUTPUT_SIZE_BYTES 48
#define KIT_SHA512_OUTPUT_SIZE_BYTES 64

#define KIT_SHA256_WORK_BLOCK_SIZE (512 / 8)
#define KIT_SHA512_WORK_BLOCK_SIZE (1024 / 8)

#define KIT_SHA2_STATE_VALUES_COUNT 8

typedef struct kit_sha256_ctx_s
{
  uint64_t processed_bytes;
  uint32_t h[KIT_SHA2_STATE_VALUES_COUNT];
  uint8_t buf[KIT_SHA256_WORK_BLOCK_SIZE];
  uint32_t buf_fill;
} kit_sha256_ctx;

typedef struct kit_sha512_ctx_s
{
  uint64_t processed_bytes[2];
  uint64_t h[KIT_SHA2_STATE_VALUES_COUNT];
  uint8_t buf[KIT_SHA512_WORK_BLOCK_SIZE];
  uint32_t buf_fill;
} kit_sha512_ctx;

void kit_sha256_init(kit_sha256_ctx * ctx);
void kit_sha256_append(kit_sha256_ctx * ctx, const uint8_t * data,
    size_t length);
void kit_sha256_finish(kit_sha256_ctx * ctx, uint8_t * output);

void kit_sha224_init(kit_sha256_ctx * ctx);
void kit_sha224_append(kit_sha256_ctx * ctx, const uint8_t * data,
    size_t length);
void kit_sha224_finish(kit_sha256_ctx * ctx, uint8_t * output);

void kit_sha512_init(kit_sha512_ctx * ctx);
void kit_sha512_append(kit_sha512_ctx * ctx, const uint8_t * data,
    size_t length);
void kit_sha512_finish(kit_sha512_ctx * ctx, uint8_t * output);

void kit_sha384_init(kit_sha512_ctx * ctx);
void kit_sha384_append(kit_sha512_ctx * ctx, const uint8_t * data,
    size_t length);
void kit_sha384_finish(kit_sha512_ctx * ctx, uint8_t * output);

void kit_sha224(uint8_t * output, const uint8_t * input, size_t length);
void kit_sha256(uint8_t * output, const uint8_t * input, size_t length);

void kit_sha384(uint8_t * output, const uint8_t * input, size_t length);
void kit_sha512(uint8_t * output, const uint8_t * input, size_t length);
