/* Copyright (c) 2024 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include <kitcryptoc/sha1_hmac.h>
#include <string.h>

void kit_sha1_hmac_init(kit_sha1_hmac_ctx * ctx, const uint8_t * key,
    size_t key_length)
{
  if (key_length > KIT_SHA1_WORK_BLOCK_SIZE) {
    kit_sha1(ctx->int_key, key, key_length);
    memset(&ctx->int_key[KIT_SHA1_OUTPUT_SIZE_BYTES], 0,
           KIT_SHA1_WORK_BLOCK_SIZE - KIT_SHA1_OUTPUT_SIZE_BYTES);
  } else if (key_length < KIT_SHA1_WORK_BLOCK_SIZE) {
    memcpy(ctx->int_key, key, key_length);
    memset(&ctx->int_key[key_length], 0,
        KIT_SHA1_WORK_BLOCK_SIZE - key_length);
  } else {
    memcpy(ctx->int_key, key, key_length);
  }

  for (size_t i = 0; i < KIT_SHA1_WORK_BLOCK_SIZE; i++)
    ctx->int_key[i] ^= 0x36;

  kit_sha1_init(&ctx->ctx);
  kit_sha1_append(&ctx->ctx, ctx->int_key, KIT_SHA1_WORK_BLOCK_SIZE);

  for (size_t i = 0; i < KIT_SHA1_WORK_BLOCK_SIZE; i++)
    ctx->int_key[i] ^= 0x36 ^ 0x5c;
}

void kit_sha1_hmac_append(kit_sha1_hmac_ctx * ctx, const uint8_t * data,
    size_t length)
{
  kit_sha1_append(&ctx->ctx, data, length);
}

void kit_sha1_hmac_finish(kit_sha1_hmac_ctx * ctx, uint8_t * output)
{
  uint8_t int_hash[KIT_SHA1_OUTPUT_SIZE_BYTES];

  kit_sha1_finish(&ctx->ctx, int_hash);

  kit_sha1_init(&ctx->ctx);
  kit_sha1_append(&ctx->ctx, ctx->int_key, KIT_SHA1_WORK_BLOCK_SIZE);
  kit_sha1_append(&ctx->ctx, int_hash, KIT_SHA1_OUTPUT_SIZE_BYTES);
  kit_sha1_finish(&ctx->ctx, output);
}

void kit_sha1_hmac(uint8_t * output, const uint8_t * input, size_t length,
    const uint8_t * key, size_t key_length)
{
  kit_sha1_hmac_ctx ctx;

  kit_sha1_hmac_init(&ctx, key, key_length);
  kit_sha1_hmac_append(&ctx, input, length);
  kit_sha1_hmac_finish(&ctx, output);
}

