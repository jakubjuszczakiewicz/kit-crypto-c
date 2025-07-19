/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include <kitcryptoc/ung.h>
#include <string.h>

#define UNG256_STEP 8
#define UNG512_STEP 16

void kit_ung_256_init(struct kit_ung_256 * ctx, kit_hash * function,
    const uint8_t * seed_bytes)
{
  ctx->hash = function;
  function(ctx->seed, seed_bytes, 32);
}

void kit_ung_256_next(struct kit_ung_256 * ctx, uint8_t * out, size_t bytes)
{
  while (bytes > UNG256_STEP) {
    ctx->hash(ctx->seed, ctx->seed, 32);
    memcpy(out, ctx->seed, UNG256_STEP);
    out += UNG256_STEP;
    bytes -= UNG256_STEP;
  }
  if (bytes) {
    ctx->hash(ctx->seed, ctx->seed, 32);
    memcpy(out, ctx->seed, bytes);
  }
}

void kit_ung_256_finish(struct kit_ung_256 * ctx)
{
  memset(ctx, 0, sizeof(*ctx));
}

void kit_ung_512_init(struct kit_ung_512 * ctx, kit_hash * function,
    const uint8_t * seed_bytes)
{
  ctx->hash = function;
  function(ctx->seed, seed_bytes, 64);
}

void kit_ung_512_next(struct kit_ung_512 * ctx, uint8_t * out, size_t bytes)
{
  while (bytes > UNG512_STEP) {
    ctx->hash(ctx->seed, ctx->seed, 64);
    memcpy(out, ctx->seed, UNG512_STEP);
    out += UNG512_STEP;
    bytes -= UNG512_STEP;
  }
  if (bytes) {
    ctx->hash(ctx->seed, ctx->seed, 64);
    memcpy(out, ctx->seed, bytes);
  }
}

void kit_ung_512_finish(struct kit_ung_512 * ctx)
{
  memset(ctx, 0, sizeof(*ctx));
}

