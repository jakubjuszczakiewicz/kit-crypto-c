/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include <kitcryptoc/sha1.h>
#include <string.h>

#ifdef BIG_ENDIAN
#define HTOBE32(x) (x)

#elif LITTLE_ENDIAN
#define HTOBE32(x) (((x) >> 24) | (((x) >> 8) & 0xFF00) | \
    (((x) << 8) & 0xFF0000) | (((x) & 0xFF) << 24))
#else
#error Unknown endian
#endif

#define ROL32(x, n) ((x) << (n) | ((x) >> (32 - (n))))

#define INIT_EXT(x, n) x[n] = ROL32(x[n-3] ^ x[n-8] ^ x[n-14] ^ x[n-16], 1)

#define SHA1_WORK_WORDS 80

#define SHA1_F(a, b, c, d, e) (ROL32(a, 5) + ((b & c) | ((~b) & d)))
#define SHA1_G(a, b, c, d, e) (ROL32(a, 5) + (b ^ c ^ d))
#define SHA1_H(a, b, c, d, e) (ROL32(a, 5) + ((b & c) | (b & d) | (c & d)))
#define SHA1_I(a, b, c, d, e) (ROL32(a, 5) + (b ^ c ^ d))

#define SHA1_FF(a, b, c, d, e, x) { \
  e += SHA1_F(a, b, c, d, e) + x + 0x5A827999; \
  b = ROL32(b, 30); \
}

#define SHA1_GG(a, b, c, d, e, x) { \
  e += SHA1_G(a, b, c, d, e) + x + 0x6ED9EBA1; \
  b = ROL32(b, 30); \
}

#define SHA1_HH(a, b, c, d, e, x) { \
  e += SHA1_H(a, b, c, d, e) + x + 0x8F1BBCDC; \
  b = ROL32(b, 30); \
}

#define SHA1_II(a, b, c, d, e, x) { \
  e += SHA1_I(a, b, c, d, e) + x + 0xCA62C1D6; \
  b = ROL32(b, 30); \
}

static const uint32_t sha1_init_vector[KIT_SHA1_STATE_VALUES_COUNT] = {
  0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
};

void kit_sha1_init(kit_sha1_ctx * ctx)
{
  for (size_t i = 0; i < KIT_SHA1_STATE_VALUES_COUNT; i++)
    ctx->h[i] = sha1_init_vector[i];

  memset(ctx->buf, 0, sizeof(ctx->buf));
  ctx->buf_fill = 0;
  ctx->processed_bytes = 0;
}

static void kit_sha1_iterate(kit_sha1_ctx * ctx, const uint32_t * data)
{
  uint32_t x[SHA1_WORK_WORDS];
  x[0] = HTOBE32(data[0]);
  x[1] = HTOBE32(data[1]);
  x[2] = HTOBE32(data[2]);
  x[3] = HTOBE32(data[3]);
  x[4] = HTOBE32(data[4]);
  x[5] = HTOBE32(data[5]);
  x[6] = HTOBE32(data[6]);
  x[7] = HTOBE32(data[7]);
  x[8] = HTOBE32(data[8]);
  x[9] = HTOBE32(data[9]);
  x[10] = HTOBE32(data[10]);
  x[11] = HTOBE32(data[11]);
  x[12] = HTOBE32(data[12]);
  x[13] = HTOBE32(data[13]);
  x[14] = HTOBE32(data[14]);
  x[15] = HTOBE32(data[15]);

  INIT_EXT(x, 16);
  INIT_EXT(x, 17);
  INIT_EXT(x, 18);
  INIT_EXT(x, 19);
  INIT_EXT(x, 20);
  INIT_EXT(x, 21);
  INIT_EXT(x, 22);
  INIT_EXT(x, 23);
  INIT_EXT(x, 24);
  INIT_EXT(x, 25);
  INIT_EXT(x, 26);
  INIT_EXT(x, 27);
  INIT_EXT(x, 28);
  INIT_EXT(x, 29);
  INIT_EXT(x, 30);
  INIT_EXT(x, 31);
  INIT_EXT(x, 32);
  INIT_EXT(x, 33);
  INIT_EXT(x, 34);
  INIT_EXT(x, 35);
  INIT_EXT(x, 36);
  INIT_EXT(x, 37);
  INIT_EXT(x, 38);
  INIT_EXT(x, 39);
  INIT_EXT(x, 40);
  INIT_EXT(x, 41);
  INIT_EXT(x, 42);
  INIT_EXT(x, 43);
  INIT_EXT(x, 44);
  INIT_EXT(x, 45);
  INIT_EXT(x, 46);
  INIT_EXT(x, 47);
  INIT_EXT(x, 48);
  INIT_EXT(x, 49);
  INIT_EXT(x, 50);
  INIT_EXT(x, 51);
  INIT_EXT(x, 52);
  INIT_EXT(x, 53);
  INIT_EXT(x, 54);
  INIT_EXT(x, 55);
  INIT_EXT(x, 56);
  INIT_EXT(x, 57);
  INIT_EXT(x, 58);
  INIT_EXT(x, 59);
  INIT_EXT(x, 60);
  INIT_EXT(x, 61);
  INIT_EXT(x, 62);
  INIT_EXT(x, 63);
  INIT_EXT(x, 64);
  INIT_EXT(x, 65);
  INIT_EXT(x, 66);
  INIT_EXT(x, 67);
  INIT_EXT(x, 68);
  INIT_EXT(x, 69);
  INIT_EXT(x, 70);
  INIT_EXT(x, 71);
  INIT_EXT(x, 72);
  INIT_EXT(x, 73);
  INIT_EXT(x, 74);
  INIT_EXT(x, 75);
  INIT_EXT(x, 76);
  INIT_EXT(x, 77);
  INIT_EXT(x, 78);
  INIT_EXT(x, 79);

  uint32_t a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3];
  uint32_t e = ctx->h[4];

  /* Round 1 */
  SHA1_FF(a, b, c, d, e, x[0]);
  SHA1_FF(e, a, b, c, d, x[1]);
  SHA1_FF(d, e, a, b, c, x[2]);
  SHA1_FF(c, d, e, a, b, x[3]);
  SHA1_FF(b, c, d, e, a, x[4]);
  SHA1_FF(a, b, c, d, e, x[5]);
  SHA1_FF(e, a, b, c, d, x[6]);
  SHA1_FF(d, e, a, b, c, x[7]);
  SHA1_FF(c, d, e, a, b, x[8]);
  SHA1_FF(b, c, d, e, a, x[9]);
  SHA1_FF(a, b, c, d, e, x[10]);
  SHA1_FF(e, a, b, c, d, x[11]);
  SHA1_FF(d, e, a, b, c, x[12]);
  SHA1_FF(c, d, e, a, b, x[13]);
  SHA1_FF(b, c, d, e, a, x[14]);
  SHA1_FF(a, b, c, d, e, x[15]);
  SHA1_FF(e, a, b, c, d, x[16]);
  SHA1_FF(d, e, a, b, c, x[17]);
  SHA1_FF(c, d, e, a, b, x[18]);
  SHA1_FF(b, c, d, e, a, x[19]);

  /* Round 2 */
  SHA1_GG(a, b, c, d, e, x[20]);
  SHA1_GG(e, a, b, c, d, x[21]);
  SHA1_GG(d, e, a, b, c, x[22]);
  SHA1_GG(c, d, e, a, b, x[23]);
  SHA1_GG(b, c, d, e, a, x[24]);
  SHA1_GG(a, b, c, d, e, x[25]);
  SHA1_GG(e, a, b, c, d, x[26]);
  SHA1_GG(d, e, a, b, c, x[27]);
  SHA1_GG(c, d, e, a, b, x[28]);
  SHA1_GG(b, c, d, e, a, x[29]);
  SHA1_GG(a, b, c, d, e, x[30]);
  SHA1_GG(e, a, b, c, d, x[31]);
  SHA1_GG(d, e, a, b, c, x[32]);
  SHA1_GG(c, d, e, a, b, x[33]);
  SHA1_GG(b, c, d, e, a, x[34]);
  SHA1_GG(a, b, c, d, e, x[35]);
  SHA1_GG(e, a, b, c, d, x[36]);
  SHA1_GG(d, e, a, b, c, x[37]);
  SHA1_GG(c, d, e, a, b, x[38]);
  SHA1_GG(b, c, d, e, a, x[39]);

  /* Round 3 */
  SHA1_HH(a, b, c, d, e, x[40]);
  SHA1_HH(e, a, b, c, d, x[41]);
  SHA1_HH(d, e, a, b, c, x[42]);
  SHA1_HH(c, d, e, a, b, x[43]);
  SHA1_HH(b, c, d, e, a, x[44]);
  SHA1_HH(a, b, c, d, e, x[45]);
  SHA1_HH(e, a, b, c, d, x[46]);
  SHA1_HH(d, e, a, b, c, x[47]);
  SHA1_HH(c, d, e, a, b, x[48]);
  SHA1_HH(b, c, d, e, a, x[49]);
  SHA1_HH(a, b, c, d, e, x[50]);
  SHA1_HH(e, a, b, c, d, x[51]);
  SHA1_HH(d, e, a, b, c, x[52]);
  SHA1_HH(c, d, e, a, b, x[53]);
  SHA1_HH(b, c, d, e, a, x[54]);
  SHA1_HH(a, b, c, d, e, x[55]);
  SHA1_HH(e, a, b, c, d, x[56]);
  SHA1_HH(d, e, a, b, c, x[57]);
  SHA1_HH(c, d, e, a, b, x[58]);
  SHA1_HH(b, c, d, e, a, x[59]);

  /* Round 4 */
  SHA1_II(a, b, c, d, e, x[60]);
  SHA1_II(e, a, b, c, d, x[61]);
  SHA1_II(d, e, a, b, c, x[62]);
  SHA1_II(c, d, e, a, b, x[63]);
  SHA1_II(b, c, d, e, a, x[64]);
  SHA1_II(a, b, c, d, e, x[65]);
  SHA1_II(e, a, b, c, d, x[66]);
  SHA1_II(d, e, a, b, c, x[67]);
  SHA1_II(c, d, e, a, b, x[68]);
  SHA1_II(b, c, d, e, a, x[69]);
  SHA1_II(a, b, c, d, e, x[70]);
  SHA1_II(e, a, b, c, d, x[71]);
  SHA1_II(d, e, a, b, c, x[72]);
  SHA1_II(c, d, e, a, b, x[73]);
  SHA1_II(b, c, d, e, a, x[74]);
  SHA1_II(a, b, c, d, e, x[75]);
  SHA1_II(e, a, b, c, d, x[76]);
  SHA1_II(d, e, a, b, c, x[77]);
  SHA1_II(c, d, e, a, b, x[78]);
  SHA1_II(b, c, d, e, a, x[79]);

  ctx->h[0] += a;
  ctx->h[1] += b;
  ctx->h[2] += c;
  ctx->h[3] += d;
  ctx->h[4] += e;
}

void kit_sha1_append(kit_sha1_ctx * ctx, const uint8_t * data, size_t length)
{
  size_t pos = 0;
  while (pos < length) {
    if ((ctx->buf_fill) || (length - pos < sizeof(ctx->buf))) {
      size_t add = sizeof(ctx->buf) - ctx->buf_fill;
      if (add > length - pos)
        add = length - pos;

      memcpy(&ctx->buf[ctx->buf_fill], &data[pos], add);
      ctx->buf_fill += add;
      if (ctx->buf_fill != sizeof(ctx->buf))
        return;
      kit_sha1_iterate(ctx, (uint32_t *)ctx->buf);
      ctx->processed_bytes += sizeof(ctx->buf);
      ctx->buf_fill = 0;
      pos += add;
    } else {
      size_t ptr = (size_t)(&data[pos]);
      if ((ptr & 0x7) == 0) {
        kit_sha1_iterate(ctx, (uint32_t *)&data[pos]);
        pos += sizeof(ctx->buf);
        ctx->processed_bytes += sizeof(ctx->buf);
      } else {
        size_t add = sizeof(ctx->buf);
        memcpy(&ctx->buf[ctx->buf_fill], &data[pos], add);
        kit_sha1_iterate(ctx, (uint32_t *)ctx->buf);
        ctx->processed_bytes += sizeof(ctx->buf);
        ctx->buf_fill = 0;
        pos += add;
      }
    }
  }
}

void kit_sha1_finish(kit_sha1_ctx * ctx, uint8_t * output)
{
  if (ctx->buf_fill == sizeof(ctx->buf)) {
    kit_sha1_iterate(ctx, (uint32_t *)ctx->buf);
    ctx->buf_fill = 0;
  }

  if (ctx->buf_fill > sizeof(ctx->buf) - ((64 / 8) + 1)) {
    ctx->buf[ctx->buf_fill] = 0x80;
    memset(&ctx->buf[ctx->buf_fill + 1], 0, sizeof(ctx->buf) - 1 -
        ctx->buf_fill);
    ctx->processed_bytes += ctx->buf_fill;
    kit_sha1_iterate(ctx, (uint32_t *)ctx->buf);

    memset(ctx->buf, 0, sizeof(ctx->buf));
  } else {
    ctx->processed_bytes += ctx->buf_fill;
    ctx->buf[ctx->buf_fill] = 0x80;
    memset(&ctx->buf[ctx->buf_fill + 1], 0, sizeof(ctx->buf) - 1 -
        ctx->buf_fill - ((64 / 8)));
  }

  uint64_t bits = 8 * ctx->processed_bytes;
  ctx->buf[sizeof(ctx->buf) - 1] = bits;
  ctx->buf[sizeof(ctx->buf) - 2] = bits >> 8;
  ctx->buf[sizeof(ctx->buf) - 3] = bits >> 16;
  ctx->buf[sizeof(ctx->buf) - 4] = bits >> 24;
  ctx->buf[sizeof(ctx->buf) - 5] = bits >> 32;
  ctx->buf[sizeof(ctx->buf) - 6] = bits >> 40;
  ctx->buf[sizeof(ctx->buf) - 7] = bits >> 48;
  ctx->buf[sizeof(ctx->buf) - 8] = bits >> 56;

  kit_sha1_iterate(ctx, (uint32_t *)ctx->buf);

  uint32_t out[5];

  out[0] = HTOBE32(ctx->h[0]);
  out[1] = HTOBE32(ctx->h[1]);
  out[2] = HTOBE32(ctx->h[2]);
  out[3] = HTOBE32(ctx->h[3]);
  out[4] = HTOBE32(ctx->h[4]);

  memcpy(output, out, KIT_SHA1_OUTPUT_SIZE_BYTES);
}

void kit_sha1(uint8_t * output, const uint8_t * input, size_t length)
{
  kit_sha1_ctx ctx;
  kit_sha1_init(&ctx);
  kit_sha1_append(&ctx, input, length);
  kit_sha1_finish(&ctx, output);
}
