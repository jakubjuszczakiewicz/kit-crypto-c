/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include <kitcryptoc/md5.h>
#include <string.h>

#if LITTLE_ENDIAN
#define HTOLE32(x) (x)

#elif BIG_ENDIAN
#define HTOLE32(x) (((x) >> 24) | (((x) >> 8) & 0xFF00) | \
    (((x) << 8) & 0xFF0000) | (((x) & 0xFF) << 24))
#else
#error Unknown endian
#endif

#define ROL32(x, n) ((x) << (n) | ((x) >> (32 - (n))))

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

#define MD5_F(X, Y, Z) ((X & Y) | (~X & Z))
#define MD5_G(X, Y, Z) ((X & Z) | (Y & ~Z))
#define MD5_H(X, Y, Z) (X ^ Y ^ Z)
#define MD5_I(X, Y, Z) (Y ^ (X | ~Z))

#define MD5_FF(a, b, c, d, x, s, ac) { \
 (a) += MD5_F ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROL32 ((a), (s)); \
 (a) += (b); \
  }
#define MD5_GG(a, b, c, d, x, s, ac) { \
 (a) += MD5_G ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROL32 ((a), (s)); \
 (a) += (b); \
  }
#define MD5_HH(a, b, c, d, x, s, ac) { \
 (a) += MD5_H ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROL32 ((a), (s)); \
 (a) += (b); \
  }
#define MD5_II(a, b, c, d, x, s, ac) { \
 (a) += MD5_I ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROL32 ((a), (s)); \
 (a) += (b); \
  }

static const uint32_t md5_init_vector[KIT_MD5_STATE_VALUES_COUNT] = {
  0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
};

void kit_md5_init(kit_md5_ctx * ctx)
{
  for (size_t i = 0; i < KIT_MD5_STATE_VALUES_COUNT; i++)
    ctx->h[i] = md5_init_vector[i];

  memset(ctx->buf, 0, sizeof(ctx->buf));
  ctx->buf_fill = 0;
  ctx->processed_bytes = 0;
}

static void kit_md5_iterate(kit_md5_ctx * ctx, const uint32_t * data)
{
  uint32_t x[16];
  x[0] = HTOLE32(data[0]);
  x[1] = HTOLE32(data[1]);
  x[2] = HTOLE32(data[2]);
  x[3] = HTOLE32(data[3]);
  x[4] = HTOLE32(data[4]);
  x[5] = HTOLE32(data[5]);
  x[6] = HTOLE32(data[6]);
  x[7] = HTOLE32(data[7]);
  x[8] = HTOLE32(data[8]);
  x[9] = HTOLE32(data[9]);
  x[10] = HTOLE32(data[10]);
  x[11] = HTOLE32(data[11]);
  x[12] = HTOLE32(data[12]);
  x[13] = HTOLE32(data[13]);
  x[14] = HTOLE32(data[14]);
  x[15] = HTOLE32(data[15]);

  uint32_t a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3];
  uint32_t tmp1, tmp2;

  /* Round 1 */
  MD5_FF(a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
  MD5_FF(d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
  MD5_FF(c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
  MD5_FF(b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
  MD5_FF(a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
  MD5_FF(d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
  MD5_FF(c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
  MD5_FF(b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
  MD5_FF(a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
  MD5_FF(d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
  MD5_FF(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
  MD5_FF(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
  MD5_FF(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
  MD5_FF(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
  MD5_FF(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
  MD5_FF(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

  /* Round 2 */
  MD5_GG(a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
  MD5_GG(d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
  MD5_GG(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
  MD5_GG(b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
  MD5_GG(a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
  MD5_GG(d, a, b, c, x[10], S22,  0x2441453); /* 22 */
  MD5_GG(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
  MD5_GG(b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
  MD5_GG(a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
  MD5_GG(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
  MD5_GG(c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
  MD5_GG(b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
  MD5_GG(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
  MD5_GG(d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
  MD5_GG(c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
  MD5_GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

  /* Round 3 */
  MD5_HH(a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
  MD5_HH(d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
  MD5_HH(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
  MD5_HH(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
  MD5_HH(a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
  MD5_HH(d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
  MD5_HH(c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
  MD5_HH(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
  MD5_HH(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
  MD5_HH(d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
  MD5_HH(c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
  MD5_HH(b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
  MD5_HH(a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
  MD5_HH(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
  MD5_HH(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
  MD5_HH(b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

  /* Round 4 */
  MD5_II(a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
  MD5_II(d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
  MD5_II(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
  MD5_II(b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
  MD5_II(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
  MD5_II(d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
  MD5_II(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
  MD5_II(b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
  MD5_II(a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
  MD5_II(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
  MD5_II(c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
  MD5_II(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
  MD5_II(a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
  MD5_II(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
  MD5_II(c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
  MD5_II(b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

  ctx->h[0] += a;
  ctx->h[1] += b;
  ctx->h[2] += c;
  ctx->h[3] += d;
}

void kit_md5_append(kit_md5_ctx * ctx, const uint8_t * data, size_t length)
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
      kit_md5_iterate(ctx, (uint32_t *)ctx->buf);
      ctx->processed_bytes += sizeof(ctx->buf);
      ctx->buf_fill = 0;
      pos += add;
    } else {
      size_t ptr = (size_t)(&data[pos]);
      if ((ptr & 0x7) == 0) {
        kit_md5_iterate(ctx, (uint32_t *)&data[pos]);
        pos += sizeof(ctx->buf);
        ctx->processed_bytes += sizeof(ctx->buf);
      } else {
        size_t add = sizeof(ctx->buf);
        memcpy(&ctx->buf[ctx->buf_fill], &data[pos], add);
        kit_md5_iterate(ctx, (uint32_t *)ctx->buf);
        ctx->processed_bytes += sizeof(ctx->buf);
        ctx->buf_fill = 0;
        pos += add;
      }
    }
  }
}

void kit_md5_finish(kit_md5_ctx * ctx, uint8_t * output)
{
  if (ctx->buf_fill == sizeof(ctx->buf)) {
    kit_md5_iterate(ctx, (uint32_t *)ctx->buf);
    ctx->buf_fill = 0;
  }

  if (ctx->buf_fill > sizeof(ctx->buf) - ((64 / 8) + 1)) {
    ctx->buf[ctx->buf_fill] = 0x80;
    memset(&ctx->buf[ctx->buf_fill + 1], 0, sizeof(ctx->buf) - 1 -
        ctx->buf_fill);
    ctx->processed_bytes += ctx->buf_fill;
    kit_md5_iterate(ctx, (uint32_t *)ctx->buf);

    memset(ctx->buf, 0, sizeof(ctx->buf));
  } else {
    ctx->processed_bytes += ctx->buf_fill;
    ctx->buf[ctx->buf_fill] = 0x80;
    memset(&ctx->buf[ctx->buf_fill + 1], 0, sizeof(ctx->buf) - 1 -
        ctx->buf_fill - ((64 / 8)));
  }

  uint64_t bits = 8 * ctx->processed_bytes;
  ctx->buf[sizeof(ctx->buf) - 1] = bits >> 56;
  ctx->buf[sizeof(ctx->buf) - 2] = bits >> 16;
  ctx->buf[sizeof(ctx->buf) - 3] = bits >> 48;
  ctx->buf[sizeof(ctx->buf) - 4] = bits >> 40;
  ctx->buf[sizeof(ctx->buf) - 5] = bits >> 32;
  ctx->buf[sizeof(ctx->buf) - 6] = bits >> 24;
  ctx->buf[sizeof(ctx->buf) - 7] = bits >> 8;
  ctx->buf[sizeof(ctx->buf) - 8] = bits;

  kit_md5_iterate(ctx, (uint32_t *)ctx->buf);

  uint32_t out[4];

  out[0] = HTOLE32(ctx->h[0]);
  out[1] = HTOLE32(ctx->h[1]);
  out[2] = HTOLE32(ctx->h[2]);
  out[3] = HTOLE32(ctx->h[3]);

  memcpy(output, out, KIT_MD5_OUTPUT_SIZE_BYTES);
}

void kit_md5(uint8_t * output, const uint8_t * input, size_t length)
{
  kit_md5_ctx ctx;
  kit_md5_init(&ctx);
  kit_md5_append(&ctx, input, length);
  kit_md5_finish(&ctx, output);
}
