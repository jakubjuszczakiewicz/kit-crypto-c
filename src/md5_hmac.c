/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include <kitcryptoc/md5_hmac.h>
#include <string.h>

void kit_md5_hmac_init(kit_md5_hmac_ctx * ctx, const uint8_t * key,
    size_t key_length)
{
  if (key_length > KIT_MD5_WORK_BLOCK_SIZE) {
    kit_md5(ctx->int_key, key, key_length);
    memset(&ctx->int_key[KIT_MD5_OUTPUT_SIZE_BYTES], 0,
           KIT_MD5_WORK_BLOCK_SIZE - KIT_MD5_OUTPUT_SIZE_BYTES);
  } else if (key_length < KIT_MD5_WORK_BLOCK_SIZE) {
    memcpy(ctx->int_key, key, key_length);
    memset(&ctx->int_key[key_length], 0,
        KIT_MD5_WORK_BLOCK_SIZE - key_length);
  } else {
    memcpy(ctx->int_key, key, key_length);
  }

  for (size_t i = 0; i < KIT_MD5_WORK_BLOCK_SIZE; i++)
    ctx->int_key[i] ^= 0x36;

  kit_md5_init(&ctx->ctx);
  kit_md5_append(&ctx->ctx, ctx->int_key, KIT_MD5_WORK_BLOCK_SIZE);

  for (size_t i = 0; i < KIT_MD5_WORK_BLOCK_SIZE; i++)
    ctx->int_key[i] ^= 0x36 ^ 0x5c;
}

void kit_md5_hmac_append(kit_md5_hmac_ctx * ctx, const uint8_t * data,
    size_t length)
{
  kit_md5_append(&ctx->ctx, data, length);
}

void kit_md5_hmac_finish(kit_md5_hmac_ctx * ctx, uint8_t * output)
{
  uint8_t int_hash[KIT_MD5_OUTPUT_SIZE_BYTES];

  kit_md5_finish(&ctx->ctx, int_hash);

  kit_md5_init(&ctx->ctx);
  kit_md5_append(&ctx->ctx, ctx->int_key, KIT_MD5_WORK_BLOCK_SIZE);
  kit_md5_append(&ctx->ctx, int_hash, KIT_MD5_OUTPUT_SIZE_BYTES);
  kit_md5_finish(&ctx->ctx, output);
}

void kit_md5_hmac(uint8_t * output, const uint8_t * input, size_t length,
    const uint8_t * key, size_t key_length)
{
  kit_md5_hmac_ctx ctx;

  kit_md5_hmac_init(&ctx, key, key_length);
  kit_md5_hmac_append(&ctx, input, length);
  kit_md5_hmac_finish(&ctx, output);
}

