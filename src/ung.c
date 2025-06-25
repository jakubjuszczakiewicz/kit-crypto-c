/* Copyright (c) 2025 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include <kitcryptoc/ung.h>
#include <string.h>

void kit_ung_256_init(struct kit_ung_256 * ctx, kit_hash * function,
    const uint8_t * seed_bytes)
{
  ctx->hash = function;
  function(ctx->seed, seed_bytes, 32);
}

void kit_ung_256_next(struct kit_ung_256 * ctx, uint8_t * out, size_t bytes)
{
  while (bytes > 4) {
    ctx->hash(ctx->seed, ctx->seed, 32);
    memcpy(out, ctx->seed, 4);
    out += 4;
    bytes -= 4;
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
  while (bytes > 8) {
    ctx->hash(ctx->seed, ctx->seed, 64);
    memcpy(out, ctx->seed, 8);
    out += 8;
    bytes -= 8;
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

