/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

#include "sha2.h"

typedef struct kit_sha256_hmac_ctx_s
{
  kit_sha256_ctx ctx;
  uint8_t int_key[KIT_SHA256_WORK_BLOCK_SIZE];
} kit_sha256_hmac_ctx;

typedef struct kit_sha512_hmac_ctx_s
{
  kit_sha512_ctx ctx;
  uint8_t int_key[KIT_SHA512_WORK_BLOCK_SIZE];
} kit_sha512_hmac_ctx;

void kit_sha224_hmac_init(kit_sha256_hmac_ctx * ctx, const uint8_t * key,
    size_t key_length);
void kit_sha224_hmac_append(kit_sha256_hmac_ctx * ctx, const uint8_t * data,
    size_t length);
void kit_sha224_hmac_finish(kit_sha256_hmac_ctx * ctx, uint8_t * output);

void kit_sha256_hmac_init(kit_sha256_hmac_ctx * ctx, const uint8_t * key,
    size_t key_length);
void kit_sha256_hmac_append(kit_sha256_hmac_ctx * ctx, const uint8_t * data,
    size_t length);
void kit_sha256_hmac_finish(kit_sha256_hmac_ctx * ctx, uint8_t * output);

void kit_sha384_hmac_init(kit_sha512_hmac_ctx * ctx, const uint8_t * key,
    size_t key_length);
void kit_sha384_hmac_append(kit_sha512_hmac_ctx * ctx, const uint8_t * data,
    size_t length);
void kit_sha384_hmac_finish(kit_sha512_hmac_ctx * ctx, uint8_t * output);

void kit_sha512_hmac_init(kit_sha512_hmac_ctx * ctx, const uint8_t * key,
    size_t key_length);
void kit_sha512_hmac_append(kit_sha512_hmac_ctx * ctx, const uint8_t * data,
    size_t length);
void kit_sha512_hmac_finish(kit_sha512_hmac_ctx * ctx, uint8_t * output);

void kit_sha224_hmac(uint8_t * output, const uint8_t * input, size_t length,
    const uint8_t * key, size_t key_length);
void kit_sha256_hmac(uint8_t * output, const uint8_t * input, size_t length,
    const uint8_t * key, size_t key_length);

void kit_sha384_hmac(uint8_t * output, const uint8_t * input, size_t length,
    const uint8_t * key, size_t key_length);
void kit_sha512_hmac(uint8_t * output, const uint8_t * input, size_t length,
    const uint8_t * key, size_t key_length);

