/* Copyright (c) 2025 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

typedef void kit_hash(uint8_t * output, const uint8_t * input, size_t length);

struct kit_ung_256
{
  kit_hash *hash;
  uint8_t seed[32];
};

struct kit_ung_512
{
  kit_hash *hash;
  uint8_t seed[64];
};

void kit_ung_256_init(struct kit_ung_256 * ctx, kit_hash * function,
    const uint8_t * seed_bytes);
void kit_ung_256_next(struct kit_ung_256 * ctx, uint8_t * out, size_t bytes);
void kit_ung_256_finish(struct kit_ung_256 * ctx);

void kit_ung_512_init(struct kit_ung_512 * ctx, kit_hash * function,
    const uint8_t * seed_bytes);
void kit_ung_512_next(struct kit_ung_512 * ctx, uint8_t * out, size_t bytes);
void kit_ung_512_finish(struct kit_ung_512 * ctx);
