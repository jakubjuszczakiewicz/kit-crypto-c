/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include <kitcryptoc/sha2_hmac.h>
#include <string.h>

void kit_sha224_hmac_init(kit_sha256_hmac_ctx * ctx, const uint8_t * key,
    size_t key_length)
{
  if (key_length > KIT_SHA256_WORK_BLOCK_SIZE) {
    kit_sha224(ctx->int_key, key, key_length);
    memset(&ctx->int_key[KIT_SHA224_OUTPUT_SIZE_BYTES], 0,
           KIT_SHA256_WORK_BLOCK_SIZE - KIT_SHA224_OUTPUT_SIZE_BYTES);
  } else if (key_length < KIT_SHA256_WORK_BLOCK_SIZE) {
    memcpy(ctx->int_key, key, key_length);
    memset(&ctx->int_key[key_length], 0,
        KIT_SHA256_WORK_BLOCK_SIZE - key_length);
  } else {
    memcpy(ctx->int_key, key, key_length);
  }

  for (size_t i = 0; i < KIT_SHA256_WORK_BLOCK_SIZE; i++)
    ctx->int_key[i] ^= 0x36;

  kit_sha224_init(&ctx->ctx);
  kit_sha256_append(&ctx->ctx, ctx->int_key, KIT_SHA256_WORK_BLOCK_SIZE);

  for (size_t i = 0; i < KIT_SHA256_WORK_BLOCK_SIZE; i++)
    ctx->int_key[i] ^= 0x36 ^ 0x5c;
}

void kit_sha224_hmac_append(kit_sha256_hmac_ctx * ctx, const uint8_t * data,
    size_t length)
{
  kit_sha256_append(&ctx->ctx, data, length);
}

void kit_sha224_hmac_finish(kit_sha256_hmac_ctx * ctx, uint8_t * output)
{
  uint8_t int_hash[KIT_SHA224_OUTPUT_SIZE_BYTES];

  kit_sha224_finish(&ctx->ctx, int_hash);

  kit_sha224_init(&ctx->ctx);
  kit_sha256_append(&ctx->ctx, ctx->int_key, KIT_SHA256_WORK_BLOCK_SIZE);
  kit_sha256_append(&ctx->ctx, int_hash, KIT_SHA224_OUTPUT_SIZE_BYTES);
  kit_sha224_finish(&ctx->ctx, output);
}

void kit_sha224_hmac(uint8_t * output, const uint8_t * input, size_t length,
    const uint8_t * key, size_t key_length)
{
  kit_sha256_hmac_ctx ctx;

  kit_sha224_hmac_init(&ctx, key, key_length);
  kit_sha224_hmac_append(&ctx, input, length);
  kit_sha224_hmac_finish(&ctx, output);
}

void kit_sha256_hmac_init(kit_sha256_hmac_ctx * ctx, const uint8_t * key,
    size_t key_length)
{
  if (key_length > KIT_SHA256_WORK_BLOCK_SIZE) {
    kit_sha256(ctx->int_key, key, key_length);
    memset(&ctx->int_key[KIT_SHA256_OUTPUT_SIZE_BYTES], 0,
           KIT_SHA256_WORK_BLOCK_SIZE - KIT_SHA256_OUTPUT_SIZE_BYTES);
  } else if (key_length < KIT_SHA256_WORK_BLOCK_SIZE) {
    memcpy(ctx->int_key, key, key_length);
    memset(&ctx->int_key[key_length], 0,
        KIT_SHA256_WORK_BLOCK_SIZE - key_length);
  } else {
    memcpy(ctx->int_key, key, key_length);
  }

  for (size_t i = 0; i < KIT_SHA256_WORK_BLOCK_SIZE; i++)
    ctx->int_key[i] ^= 0x36;

  kit_sha256_init(&ctx->ctx);
  kit_sha256_append(&ctx->ctx, ctx->int_key, KIT_SHA256_WORK_BLOCK_SIZE);

  for (size_t i = 0; i < KIT_SHA256_WORK_BLOCK_SIZE; i++)
    ctx->int_key[i] ^= 0x36 ^ 0x5c;
}

void kit_sha256_hmac_append(kit_sha256_hmac_ctx * ctx, const uint8_t * data,
    size_t length)
{
  kit_sha256_append(&ctx->ctx, data, length);
}

void kit_sha256_hmac_finish(kit_sha256_hmac_ctx * ctx, uint8_t * output)
{
  uint8_t int_hash[KIT_SHA256_OUTPUT_SIZE_BYTES];

  kit_sha256_finish(&ctx->ctx, int_hash);

  kit_sha256_init(&ctx->ctx);
  kit_sha256_append(&ctx->ctx, ctx->int_key, KIT_SHA256_WORK_BLOCK_SIZE);
  kit_sha256_append(&ctx->ctx, int_hash, KIT_SHA256_OUTPUT_SIZE_BYTES);
  kit_sha256_finish(&ctx->ctx, output);
}

void kit_sha256_hmac(uint8_t * output, const uint8_t * input, size_t length,
    const uint8_t * key, size_t key_length)
{
  kit_sha256_hmac_ctx ctx;

  kit_sha256_hmac_init(&ctx, key, key_length);
  kit_sha256_hmac_append(&ctx, input, length);
  kit_sha256_hmac_finish(&ctx, output);
}

void kit_sha384_hmac_init(kit_sha512_hmac_ctx * ctx, const uint8_t * key,
    size_t key_length)
{
  if (key_length > KIT_SHA512_WORK_BLOCK_SIZE) {
    kit_sha384(ctx->int_key, key, key_length);
    memset(&ctx->int_key[KIT_SHA384_OUTPUT_SIZE_BYTES], 0,
           KIT_SHA512_WORK_BLOCK_SIZE - KIT_SHA384_OUTPUT_SIZE_BYTES);
  } else if (key_length < KIT_SHA512_WORK_BLOCK_SIZE) {
    memcpy(ctx->int_key, key, key_length);
    memset(&ctx->int_key[key_length], 0,
        KIT_SHA512_WORK_BLOCK_SIZE - key_length);
  } else {
    memcpy(ctx->int_key, key, key_length);
  }

  for (size_t i = 0; i < KIT_SHA512_WORK_BLOCK_SIZE; i++)
    ctx->int_key[i] ^= 0x36;

  kit_sha384_init(&ctx->ctx);
  kit_sha512_append(&ctx->ctx, ctx->int_key, KIT_SHA512_WORK_BLOCK_SIZE);

  for (size_t i = 0; i < KIT_SHA512_WORK_BLOCK_SIZE; i++)
    ctx->int_key[i] ^= 0x36 ^ 0x5c;
}

void kit_sha384_hmac_append(kit_sha512_hmac_ctx * ctx, const uint8_t * data,
    size_t length)
{
  kit_sha512_append(&ctx->ctx, data, length);
}

void kit_sha384_hmac_finish(kit_sha512_hmac_ctx * ctx, uint8_t * output)
{
  uint8_t int_hash[KIT_SHA384_OUTPUT_SIZE_BYTES];

  kit_sha384_finish(&ctx->ctx, int_hash);

  kit_sha384_init(&ctx->ctx);
  kit_sha512_append(&ctx->ctx, ctx->int_key, KIT_SHA512_WORK_BLOCK_SIZE);
  kit_sha512_append(&ctx->ctx, int_hash, KIT_SHA384_OUTPUT_SIZE_BYTES);
  kit_sha384_finish(&ctx->ctx, output);
}

void kit_sha384_hmac(uint8_t * output, const uint8_t * input, size_t length,
    const uint8_t * key, size_t key_length)
{
  kit_sha512_hmac_ctx ctx;

  kit_sha384_hmac_init(&ctx, key, key_length);
  kit_sha384_hmac_append(&ctx, input, length);
  kit_sha384_hmac_finish(&ctx, output);
}

void kit_sha512_hmac_init(kit_sha512_hmac_ctx * ctx, const uint8_t * key,
    size_t key_length)
{
  if (key_length > KIT_SHA512_WORK_BLOCK_SIZE) {
    kit_sha512(ctx->int_key, key, key_length);
    memset(&ctx->int_key[KIT_SHA512_OUTPUT_SIZE_BYTES], 0,
           KIT_SHA512_WORK_BLOCK_SIZE - KIT_SHA512_OUTPUT_SIZE_BYTES);
  } else if (key_length < KIT_SHA512_WORK_BLOCK_SIZE) {
    memcpy(ctx->int_key, key, key_length);
    memset(&ctx->int_key[key_length], 0,
        KIT_SHA512_WORK_BLOCK_SIZE - key_length);
  } else {
    memcpy(ctx->int_key, key, key_length);
  }

  for (size_t i = 0; i < KIT_SHA512_WORK_BLOCK_SIZE; i++)
    ctx->int_key[i] ^= 0x36;

  kit_sha512_init(&ctx->ctx);
  kit_sha512_append(&ctx->ctx, ctx->int_key, KIT_SHA512_WORK_BLOCK_SIZE);

  for (size_t i = 0; i < KIT_SHA512_WORK_BLOCK_SIZE; i++)
    ctx->int_key[i] ^= 0x36 ^ 0x5c;
}

void kit_sha512_hmac_append(kit_sha512_hmac_ctx * ctx, const uint8_t * data,
    size_t length)
{
  kit_sha512_append(&ctx->ctx, data, length);
}

void kit_sha512_hmac_finish(kit_sha512_hmac_ctx * ctx, uint8_t * output)
{
  uint8_t int_hash[KIT_SHA512_OUTPUT_SIZE_BYTES];

  kit_sha512_finish(&ctx->ctx, int_hash);

  kit_sha512_init(&ctx->ctx);
  kit_sha512_append(&ctx->ctx, ctx->int_key, KIT_SHA512_WORK_BLOCK_SIZE);
  kit_sha512_append(&ctx->ctx, int_hash, KIT_SHA512_OUTPUT_SIZE_BYTES);
  kit_sha512_finish(&ctx->ctx, output);
}

void kit_sha512_hmac(uint8_t * output, const uint8_t * input, size_t length,
    const uint8_t * key, size_t key_length)
{
  kit_sha512_hmac_ctx ctx;

  kit_sha512_hmac_init(&ctx, key, key_length);
  kit_sha512_hmac_append(&ctx, input, length);
  kit_sha512_hmac_finish(&ctx, output);
}
