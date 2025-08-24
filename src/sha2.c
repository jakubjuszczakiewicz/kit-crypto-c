/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include <kitcryptoc/sha2.h>
#include <string.h>

#ifdef BIG_ENDIAN
#define HTOBE32(x) (x)
#define HTOBE64(x) (x)

#elif LITTLE_ENDIAN
#define HTOBE32(x) (((x) >> 24) | (((x) >> 8) & 0xFF00) | \
    (((x) << 8) & 0xFF0000) | (((x) & 0xFF) << 24))
#define HTOBE64(x) (((x) >> 56) | (((x) >> 40) & 0xFF00) | \
    (((x) >> 24) & 0xFF0000) | (((x) >> 8) & 0xFF000000) | \
    (((x) & 0xFF000000) << 8) | (((x) & 0xFF0000) << 24) | \
    (((x) & 0xFF00) << 40) | ((x) << 56))
#else
#error Unknown endian
#endif


#define ROR32(x, n) ((x) >> (n) | ((x) << (32 - (n))))
#define ROR64(x, n) ((x) >> (n) | ((x) << (64 - (n))))

#define SHA256_INIT_F1(i) \
    (ROR32(w[i - 15], 7) ^ ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3))
#define SHA256_INIT_F2(i) \
    (ROR32(w[i - 2], 17) ^ ROR32(w[i - 2], 19) ^ (w[i - 2] >> 10))
#define SHA256_INIT_EXP(i) \
    w[i] = w[i - 16] + SHA256_INIT_F1(i) + w[i - 7] + SHA256_INIT_F2(i)

#define SHA256_STEP(a, b, c, d, e, f, g, h, n) \
    tmp1 = h + (ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25)) + \
      ((e & f) ^ ((~e) & g)) + sha256_init_round_vector[n] + w[n]; \
    tmp2 = (ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22)) + \
      ((a & b) ^ (a & c) ^ (b & c)); \
    d += tmp1; \
    h = tmp1 + tmp2

#define SHA512_INIT_F1(i) \
    (ROR64(w[i - 15], 1) ^ ROR64(w[i - 15], 8) ^ (w[i - 15] >> 7))
#define SHA512_INIT_F2(i) \
    (ROR64(w[i - 2], 19) ^ ROR64(w[i - 2], 61) ^ (w[i - 2] >> 6))
#define SHA512_INIT_EXP(i) \
    w[i] = w[i - 16] + SHA512_INIT_F1(i) + w[i - 7] + SHA512_INIT_F2(i)

#define SHA512_STEP(a, b, c, d, e, f, g, h, n) \
    tmp1 = h + (ROR64(e, 14) ^ ROR64(e, 18) ^ ROR64(e, 41)) + \
      ((e & f) ^ ((~e) & g)) + sha512_init_round_vector[n] + w[n]; \
    tmp2 = (ROR64(a, 28) ^ ROR64(a, 34) ^ ROR64(a, 39)) + \
      ((a & b) ^ (a & c) ^ (b & c)); \
    d += tmp1; \
    h = tmp1 + tmp2

static const uint32_t sha256_init_vector[8] = {
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
  0x1f83d9ab, 0x5be0cd19
};

static const uint32_t sha224_init_vector[8] = {
  0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511,
  0x64f98fa7, 0xbefa4fa4
};

static const uint32_t sha256_init_round_vector[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const uint64_t sha512_init_vector[8] = {
  0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b,
  0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
  0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

static const uint64_t sha384_init_vector[8] = {
  0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17,
  0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511,
  0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
};

const uint64_t sha512_init_round_vector[80] = {
  0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
  0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
  0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
  0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
  0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
  0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
  0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
  0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
  0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
  0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
  0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
  0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
  0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
  0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
  0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
  0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
  0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
  0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
  0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
  0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
  0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
  0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
  0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
  0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
  0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
  0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
  0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

#ifdef ALG_SHA2_ASM_X86_64
int is_sse41_supported(void);
#else
static int is_sse41_supported(void)
{
  return 0;
}
#endif

void kit_sha256_init(kit_sha256_ctx * ctx)
{
  for (size_t i = 0; i < 8; i++)
    ctx->h[i] = sha256_init_vector[i];

  memset(ctx->buf, 0, sizeof(ctx->buf));
  ctx->buf_fill = 0;
  ctx->processed_bytes = 0;
}

static void kit_sha256_iterate(kit_sha256_ctx * ctx, const uint32_t * data)
{
  uint32_t w[64];
  w[0] = HTOBE32(data[0]);
  w[1] = HTOBE32(data[1]);
  w[2] = HTOBE32(data[2]);
  w[3] = HTOBE32(data[3]);
  w[4] = HTOBE32(data[4]);
  w[5] = HTOBE32(data[5]);
  w[6] = HTOBE32(data[6]);
  w[7] = HTOBE32(data[7]);
  w[8] = HTOBE32(data[8]);
  w[9] = HTOBE32(data[9]);
  w[10] = HTOBE32(data[10]);
  w[11] = HTOBE32(data[11]);
  w[12] = HTOBE32(data[12]);
  w[13] = HTOBE32(data[13]);
  w[14] = HTOBE32(data[14]);
  w[15] = HTOBE32(data[15]);

  SHA256_INIT_EXP(16);
  SHA256_INIT_EXP(17);
  SHA256_INIT_EXP(18);
  SHA256_INIT_EXP(19);
  SHA256_INIT_EXP(20);
  SHA256_INIT_EXP(21);
  SHA256_INIT_EXP(22);
  SHA256_INIT_EXP(23);
  SHA256_INIT_EXP(24);
  SHA256_INIT_EXP(25);
  SHA256_INIT_EXP(26);
  SHA256_INIT_EXP(27);
  SHA256_INIT_EXP(28);
  SHA256_INIT_EXP(29);
  SHA256_INIT_EXP(30);
  SHA256_INIT_EXP(31);
  SHA256_INIT_EXP(32);
  SHA256_INIT_EXP(33);
  SHA256_INIT_EXP(34);
  SHA256_INIT_EXP(35);
  SHA256_INIT_EXP(36);
  SHA256_INIT_EXP(37);
  SHA256_INIT_EXP(38);
  SHA256_INIT_EXP(39);
  SHA256_INIT_EXP(40);
  SHA256_INIT_EXP(41);
  SHA256_INIT_EXP(42);
  SHA256_INIT_EXP(43);
  SHA256_INIT_EXP(44);
  SHA256_INIT_EXP(45);
  SHA256_INIT_EXP(46);
  SHA256_INIT_EXP(47);
  SHA256_INIT_EXP(48);
  SHA256_INIT_EXP(49);
  SHA256_INIT_EXP(50);
  SHA256_INIT_EXP(51);
  SHA256_INIT_EXP(52);
  SHA256_INIT_EXP(53);
  SHA256_INIT_EXP(54);
  SHA256_INIT_EXP(55);
  SHA256_INIT_EXP(56);
  SHA256_INIT_EXP(57);
  SHA256_INIT_EXP(58);
  SHA256_INIT_EXP(59);
  SHA256_INIT_EXP(60);
  SHA256_INIT_EXP(61);
  SHA256_INIT_EXP(62);
  SHA256_INIT_EXP(63);

  uint32_t a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3];
  uint32_t e = ctx->h[4], f = ctx->h[5], g = ctx->h[6], h = ctx->h[7];
  uint32_t tmp1, tmp2;

  SHA256_STEP(a, b, c, d, e, f, g, h, 0);
  SHA256_STEP(h, a, b, c, d, e, f, g, 1);
  SHA256_STEP(g, h, a, b, c, d, e, f, 2);
  SHA256_STEP(f, g, h, a, b, c, d, e, 3);
  SHA256_STEP(e, f, g, h, a, b, c, d, 4);
  SHA256_STEP(d, e, f, g, h, a, b, c, 5);
  SHA256_STEP(c, d, e, f, g, h, a, b, 6);
  SHA256_STEP(b, c, d, e, f, g, h, a, 7);
  SHA256_STEP(a, b, c, d, e, f, g, h, 8);
  SHA256_STEP(h, a, b, c, d, e, f, g, 9);
  SHA256_STEP(g, h, a, b, c, d, e, f, 10);
  SHA256_STEP(f, g, h, a, b, c, d, e, 11);
  SHA256_STEP(e, f, g, h, a, b, c, d, 12);
  SHA256_STEP(d, e, f, g, h, a, b, c, 13);
  SHA256_STEP(c, d, e, f, g, h, a, b, 14);
  SHA256_STEP(b, c, d, e, f, g, h, a, 15);
  SHA256_STEP(a, b, c, d, e, f, g, h, 16);
  SHA256_STEP(h, a, b, c, d, e, f, g, 17);
  SHA256_STEP(g, h, a, b, c, d, e, f, 18);
  SHA256_STEP(f, g, h, a, b, c, d, e, 19);
  SHA256_STEP(e, f, g, h, a, b, c, d, 20);
  SHA256_STEP(d, e, f, g, h, a, b, c, 21);
  SHA256_STEP(c, d, e, f, g, h, a, b, 22);
  SHA256_STEP(b, c, d, e, f, g, h, a, 23);
  SHA256_STEP(a, b, c, d, e, f, g, h, 24);
  SHA256_STEP(h, a, b, c, d, e, f, g, 25);
  SHA256_STEP(g, h, a, b, c, d, e, f, 26);
  SHA256_STEP(f, g, h, a, b, c, d, e, 27);
  SHA256_STEP(e, f, g, h, a, b, c, d, 28);
  SHA256_STEP(d, e, f, g, h, a, b, c, 29);
  SHA256_STEP(c, d, e, f, g, h, a, b, 30);
  SHA256_STEP(b, c, d, e, f, g, h, a, 31);
  SHA256_STEP(a, b, c, d, e, f, g, h, 32);
  SHA256_STEP(h, a, b, c, d, e, f, g, 33);
  SHA256_STEP(g, h, a, b, c, d, e, f, 34);
  SHA256_STEP(f, g, h, a, b, c, d, e, 35);
  SHA256_STEP(e, f, g, h, a, b, c, d, 36);
  SHA256_STEP(d, e, f, g, h, a, b, c, 37);
  SHA256_STEP(c, d, e, f, g, h, a, b, 38);
  SHA256_STEP(b, c, d, e, f, g, h, a, 39);
  SHA256_STEP(a, b, c, d, e, f, g, h, 40);
  SHA256_STEP(h, a, b, c, d, e, f, g, 41);
  SHA256_STEP(g, h, a, b, c, d, e, f, 42);
  SHA256_STEP(f, g, h, a, b, c, d, e, 43);
  SHA256_STEP(e, f, g, h, a, b, c, d, 44);
  SHA256_STEP(d, e, f, g, h, a, b, c, 45);
  SHA256_STEP(c, d, e, f, g, h, a, b, 46);
  SHA256_STEP(b, c, d, e, f, g, h, a, 47);
  SHA256_STEP(a, b, c, d, e, f, g, h, 48);
  SHA256_STEP(h, a, b, c, d, e, f, g, 49);
  SHA256_STEP(g, h, a, b, c, d, e, f, 50);
  SHA256_STEP(f, g, h, a, b, c, d, e, 51);
  SHA256_STEP(e, f, g, h, a, b, c, d, 52);
  SHA256_STEP(d, e, f, g, h, a, b, c, 53);
  SHA256_STEP(c, d, e, f, g, h, a, b, 54);
  SHA256_STEP(b, c, d, e, f, g, h, a, 55);
  SHA256_STEP(a, b, c, d, e, f, g, h, 56);
  SHA256_STEP(h, a, b, c, d, e, f, g, 57);
  SHA256_STEP(g, h, a, b, c, d, e, f, 58);
  SHA256_STEP(f, g, h, a, b, c, d, e, 59);
  SHA256_STEP(e, f, g, h, a, b, c, d, 60);
  SHA256_STEP(d, e, f, g, h, a, b, c, 61);
  SHA256_STEP(c, d, e, f, g, h, a, b, 62);
  SHA256_STEP(b, c, d, e, f, g, h, a, 63);

  ctx->h[0] += a;
  ctx->h[1] += b;
  ctx->h[2] += c;
  ctx->h[3] += d;
  ctx->h[4] += e;
  ctx->h[5] += f;
  ctx->h[6] += g;
  ctx->h[7] += h;
}

void kit_sha256_append(kit_sha256_ctx * ctx,
    const uint8_t * data, size_t length)
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
      kit_sha256_iterate(ctx, (uint32_t *)ctx->buf);
      ctx->processed_bytes += sizeof(ctx->buf);
      ctx->buf_fill = 0;
      pos += add;
    } else {
      size_t ptr = (size_t)(&data[pos]);
      if ((ptr & 0xF) == 0) {
        kit_sha256_iterate(ctx, (uint32_t *)&data[pos]);
        pos += sizeof(ctx->buf);
        ctx->processed_bytes += sizeof(ctx->buf);
      } else {
        size_t add = sizeof(ctx->buf);
        memcpy(&ctx->buf, &data[pos], add);
        kit_sha256_iterate(ctx, (uint32_t *)ctx->buf);
        ctx->processed_bytes += sizeof(ctx->buf);
        ctx->buf_fill = 0;
        pos += add;
      }
    }
  }
}

void kit_sha256_finish_int(kit_sha256_ctx * ctx, uint8_t * output, int len)
{
  if (ctx->buf_fill == sizeof(ctx->buf)) {
    kit_sha256_iterate(ctx, (uint32_t *)ctx->buf);
    ctx->buf_fill = 0;
  }

  if (ctx->buf_fill > sizeof(ctx->buf) - ((64 / 8) + 1)) {
    ctx->buf[ctx->buf_fill] = 0x80;
    memset(&ctx->buf[ctx->buf_fill + 1], 0, sizeof(ctx->buf) - 1 -
        ctx->buf_fill);
    ctx->processed_bytes += ctx->buf_fill;
    kit_sha256_iterate(ctx, (uint32_t *)ctx->buf);

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

  kit_sha256_iterate(ctx, (uint32_t *)ctx->buf);

  uint32_t out[8];

  out[0] = HTOBE32(ctx->h[0]);
  out[1] = HTOBE32(ctx->h[1]);
  out[2] = HTOBE32(ctx->h[2]);
  out[3] = HTOBE32(ctx->h[3]);
  out[4] = HTOBE32(ctx->h[4]);
  out[5] = HTOBE32(ctx->h[5]);
  out[6] = HTOBE32(ctx->h[6]);
  if (len) {
    out[7] = HTOBE32(ctx->h[7]);
    memcpy(output, out, KIT_SHA256_OUTPUT_SIZE_BYTES);
  } else {
    memcpy(output, out, KIT_SHA224_OUTPUT_SIZE_BYTES);
  }
}

void kit_sha256_finish(kit_sha256_ctx * ctx, uint8_t * output)
{
  kit_sha256_finish_int(ctx, output, 1);
}

void kit_sha256(uint8_t * output, const uint8_t * input, size_t length)
{
  kit_sha256_ctx ctx;
  kit_sha256_init(&ctx);
  kit_sha256_append(&ctx, input, length);
  kit_sha256_finish(&ctx, output);
}

void kit_sha224_init(kit_sha256_ctx * ctx)
{
  for (size_t i = 0; i < 8; i++)
    ctx->h[i] = sha224_init_vector[i];

  memset(ctx->buf, 0, sizeof(ctx->buf));
  ctx->buf_fill = 0;
  ctx->processed_bytes = 0;
}

void kit_sha224_append(kit_sha256_ctx * ctx, const uint8_t * data,
    size_t length)
{
  kit_sha256_append(ctx, data, length);
}

void kit_sha224_finish(kit_sha256_ctx * ctx, uint8_t * output)
{
  kit_sha256_finish_int(ctx, output, 0);
}

void kit_sha224(uint8_t * output, const uint8_t * input, size_t length)
{
  kit_sha256_ctx ctx;
  kit_sha224_init(&ctx);
  kit_sha256_append(&ctx, input, length);
  kit_sha224_finish(&ctx, output);
}

void kit_sha512_init(kit_sha512_ctx * ctx)
{
  for (size_t i = 0; i < 8; i++)
    ctx->h[i] = sha512_init_vector[i];

  memset(ctx->buf, 0, sizeof(ctx->buf));
  ctx->buf_fill = 0;
  ctx->processed_bytes[0] = 0;
  ctx->processed_bytes[1] = 0;
}

#ifdef ALG_SHA2_ASM_X86_64
static void kit_sha512_asm_init(uint64_t * ctx, const uint64_t * data);
static void kit_sha512_iterate_c(uint64_t * ctx, const uint64_t * data);

void (*kit_sha512_iterate)(uint64_t * ctx, const uint64_t * data) =
    kit_sha512_asm_init;

void kit_sha512_iterate_asm(uint64_t * ctx, const uint64_t * data);

static void kit_sha512_asm_init(uint64_t * ctx, const uint64_t * data)
{
  if (is_sse41_supported()) {
    kit_sha512_iterate = kit_sha512_iterate_asm;
  } else {
    kit_sha512_iterate = kit_sha512_iterate_c;
  }
  kit_sha512_iterate(ctx, data);
}

#else
#define kit_sha512_iterate kit_sha512_iterate_c
#endif

static void kit_sha512_iterate_c(uint64_t * ctx, const uint64_t * data)
{
  uint64_t w[80];

  w[0] = HTOBE64(data[0]);
  w[1] = HTOBE64(data[1]);
  w[2] = HTOBE64(data[2]);
  w[3] = HTOBE64(data[3]);
  w[4] = HTOBE64(data[4]);
  w[5] = HTOBE64(data[5]);
  w[6] = HTOBE64(data[6]);
  w[7] = HTOBE64(data[7]);
  w[8] = HTOBE64(data[8]);
  w[9] = HTOBE64(data[9]);
  w[10] = HTOBE64(data[10]);
  w[11] = HTOBE64(data[11]);
  w[12] = HTOBE64(data[12]);
  w[13] = HTOBE64(data[13]);
  w[14] = HTOBE64(data[14]);
  w[15] = HTOBE64(data[15]);

  SHA512_INIT_EXP(16);
  SHA512_INIT_EXP(17);
  SHA512_INIT_EXP(18);
  SHA512_INIT_EXP(19);
  SHA512_INIT_EXP(20);
  SHA512_INIT_EXP(21);
  SHA512_INIT_EXP(22);
  SHA512_INIT_EXP(23);
  SHA512_INIT_EXP(24);
  SHA512_INIT_EXP(25);
  SHA512_INIT_EXP(26);
  SHA512_INIT_EXP(27);
  SHA512_INIT_EXP(28);
  SHA512_INIT_EXP(29);
  SHA512_INIT_EXP(30);
  SHA512_INIT_EXP(31);
  SHA512_INIT_EXP(32);
  SHA512_INIT_EXP(33);
  SHA512_INIT_EXP(34);
  SHA512_INIT_EXP(35);
  SHA512_INIT_EXP(36);
  SHA512_INIT_EXP(37);
  SHA512_INIT_EXP(38);
  SHA512_INIT_EXP(39);
  SHA512_INIT_EXP(40);
  SHA512_INIT_EXP(41);
  SHA512_INIT_EXP(42);
  SHA512_INIT_EXP(43);
  SHA512_INIT_EXP(44);
  SHA512_INIT_EXP(45);
  SHA512_INIT_EXP(46);
  SHA512_INIT_EXP(47);
  SHA512_INIT_EXP(48);
  SHA512_INIT_EXP(49);
  SHA512_INIT_EXP(50);
  SHA512_INIT_EXP(51);
  SHA512_INIT_EXP(52);
  SHA512_INIT_EXP(53);
  SHA512_INIT_EXP(54);
  SHA512_INIT_EXP(55);
  SHA512_INIT_EXP(56);
  SHA512_INIT_EXP(57);
  SHA512_INIT_EXP(58);
  SHA512_INIT_EXP(59);
  SHA512_INIT_EXP(60);
  SHA512_INIT_EXP(61);
  SHA512_INIT_EXP(62);
  SHA512_INIT_EXP(63);
  SHA512_INIT_EXP(64);
  SHA512_INIT_EXP(65);
  SHA512_INIT_EXP(66);
  SHA512_INIT_EXP(67);
  SHA512_INIT_EXP(68);
  SHA512_INIT_EXP(69);
  SHA512_INIT_EXP(70);
  SHA512_INIT_EXP(71);
  SHA512_INIT_EXP(72);
  SHA512_INIT_EXP(73);
  SHA512_INIT_EXP(74);
  SHA512_INIT_EXP(75);
  SHA512_INIT_EXP(76);
  SHA512_INIT_EXP(77);
  SHA512_INIT_EXP(78);
  SHA512_INIT_EXP(79);

  uint64_t a = ctx[0], b = ctx[1], c = ctx[2], d = ctx[3];
  uint64_t e = ctx[4], f = ctx[5], g = ctx[6], h = ctx[7];
  uint64_t tmp1, tmp2;

  SHA512_STEP(a, b, c, d, e, f, g, h, 0);
  SHA512_STEP(h, a, b, c, d, e, f, g, 1);
  SHA512_STEP(g, h, a, b, c, d, e, f, 2);
  SHA512_STEP(f, g, h, a, b, c, d, e, 3);
  SHA512_STEP(e, f, g, h, a, b, c, d, 4);
  SHA512_STEP(d, e, f, g, h, a, b, c, 5);
  SHA512_STEP(c, d, e, f, g, h, a, b, 6);
  SHA512_STEP(b, c, d, e, f, g, h, a, 7);
  SHA512_STEP(a, b, c, d, e, f, g, h, 8);
  SHA512_STEP(h, a, b, c, d, e, f, g, 9);
  SHA512_STEP(g, h, a, b, c, d, e, f, 10);
  SHA512_STEP(f, g, h, a, b, c, d, e, 11);
  SHA512_STEP(e, f, g, h, a, b, c, d, 12);
  SHA512_STEP(d, e, f, g, h, a, b, c, 13);
  SHA512_STEP(c, d, e, f, g, h, a, b, 14);
  SHA512_STEP(b, c, d, e, f, g, h, a, 15);
  SHA512_STEP(a, b, c, d, e, f, g, h, 16);
  SHA512_STEP(h, a, b, c, d, e, f, g, 17);
  SHA512_STEP(g, h, a, b, c, d, e, f, 18);
  SHA512_STEP(f, g, h, a, b, c, d, e, 19);
  SHA512_STEP(e, f, g, h, a, b, c, d, 20);
  SHA512_STEP(d, e, f, g, h, a, b, c, 21);
  SHA512_STEP(c, d, e, f, g, h, a, b, 22);
  SHA512_STEP(b, c, d, e, f, g, h, a, 23);
  SHA512_STEP(a, b, c, d, e, f, g, h, 24);
  SHA512_STEP(h, a, b, c, d, e, f, g, 25);
  SHA512_STEP(g, h, a, b, c, d, e, f, 26);
  SHA512_STEP(f, g, h, a, b, c, d, e, 27);
  SHA512_STEP(e, f, g, h, a, b, c, d, 28);
  SHA512_STEP(d, e, f, g, h, a, b, c, 29);
  SHA512_STEP(c, d, e, f, g, h, a, b, 30);
  SHA512_STEP(b, c, d, e, f, g, h, a, 31);
  SHA512_STEP(a, b, c, d, e, f, g, h, 32);
  SHA512_STEP(h, a, b, c, d, e, f, g, 33);
  SHA512_STEP(g, h, a, b, c, d, e, f, 34);
  SHA512_STEP(f, g, h, a, b, c, d, e, 35);
  SHA512_STEP(e, f, g, h, a, b, c, d, 36);
  SHA512_STEP(d, e, f, g, h, a, b, c, 37);
  SHA512_STEP(c, d, e, f, g, h, a, b, 38);
  SHA512_STEP(b, c, d, e, f, g, h, a, 39);
  SHA512_STEP(a, b, c, d, e, f, g, h, 40);
  SHA512_STEP(h, a, b, c, d, e, f, g, 41);
  SHA512_STEP(g, h, a, b, c, d, e, f, 42);
  SHA512_STEP(f, g, h, a, b, c, d, e, 43);
  SHA512_STEP(e, f, g, h, a, b, c, d, 44);
  SHA512_STEP(d, e, f, g, h, a, b, c, 45);
  SHA512_STEP(c, d, e, f, g, h, a, b, 46);
  SHA512_STEP(b, c, d, e, f, g, h, a, 47);
  SHA512_STEP(a, b, c, d, e, f, g, h, 48);
  SHA512_STEP(h, a, b, c, d, e, f, g, 49);
  SHA512_STEP(g, h, a, b, c, d, e, f, 50);
  SHA512_STEP(f, g, h, a, b, c, d, e, 51);
  SHA512_STEP(e, f, g, h, a, b, c, d, 52);
  SHA512_STEP(d, e, f, g, h, a, b, c, 53);
  SHA512_STEP(c, d, e, f, g, h, a, b, 54);
  SHA512_STEP(b, c, d, e, f, g, h, a, 55);
  SHA512_STEP(a, b, c, d, e, f, g, h, 56);
  SHA512_STEP(h, a, b, c, d, e, f, g, 57);
  SHA512_STEP(g, h, a, b, c, d, e, f, 58);
  SHA512_STEP(f, g, h, a, b, c, d, e, 59);
  SHA512_STEP(e, f, g, h, a, b, c, d, 60);
  SHA512_STEP(d, e, f, g, h, a, b, c, 61);
  SHA512_STEP(c, d, e, f, g, h, a, b, 62);
  SHA512_STEP(b, c, d, e, f, g, h, a, 63);
  SHA512_STEP(a, b, c, d, e, f, g, h, 64);
  SHA512_STEP(h, a, b, c, d, e, f, g, 65);
  SHA512_STEP(g, h, a, b, c, d, e, f, 66);
  SHA512_STEP(f, g, h, a, b, c, d, e, 67);
  SHA512_STEP(e, f, g, h, a, b, c, d, 68);
  SHA512_STEP(d, e, f, g, h, a, b, c, 69);
  SHA512_STEP(c, d, e, f, g, h, a, b, 70);
  SHA512_STEP(b, c, d, e, f, g, h, a, 71);
  SHA512_STEP(a, b, c, d, e, f, g, h, 72);
  SHA512_STEP(h, a, b, c, d, e, f, g, 73);
  SHA512_STEP(g, h, a, b, c, d, e, f, 74);
  SHA512_STEP(f, g, h, a, b, c, d, e, 75);
  SHA512_STEP(e, f, g, h, a, b, c, d, 76);
  SHA512_STEP(d, e, f, g, h, a, b, c, 77);
  SHA512_STEP(c, d, e, f, g, h, a, b, 78);
  SHA512_STEP(b, c, d, e, f, g, h, a, 79);

  ctx[0] += a;
  ctx[1] += b;
  ctx[2] += c;
  ctx[3] += d;
  ctx[4] += e;
  ctx[5] += f;
  ctx[6] += g;
  ctx[7] += h;
}

void kit_sha512_append(kit_sha512_ctx * ctx, const uint8_t * data,
    size_t length)
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
      kit_sha512_iterate(ctx->h, (uint64_t *)ctx->buf);
      ctx->processed_bytes[0] += sizeof(ctx->buf);
      if (ctx->processed_bytes[0] < sizeof(ctx->buf))
        ctx->processed_bytes[1]++;
      ctx->buf_fill = 0;
      pos += add;
    } else {
      size_t ptr = (size_t)(&data[pos]);
      if ((ptr & 0xF) == 0) {
        kit_sha512_iterate(ctx->h, (uint64_t *)&data[pos]);
        pos += sizeof(ctx->buf);
        ctx->processed_bytes[0] += sizeof(ctx->buf);
        if (ctx->processed_bytes[0] < sizeof(ctx->buf))
          ctx->processed_bytes[1]++;
      } else {
        size_t add = sizeof(ctx->buf);
        memcpy(&ctx->buf, &data[pos], add);
        kit_sha512_iterate(ctx->h, (uint64_t *)ctx->buf);
        ctx->processed_bytes[0] += sizeof(ctx->buf);
        if (ctx->processed_bytes[0] < sizeof(ctx->buf))
          ctx->processed_bytes[1]++;
        ctx->buf_fill = 0;
        pos += add;
      }
    }
  }
}

void kit_sha512_finish_int(kit_sha512_ctx * ctx, uint8_t * output, int len)
{
  if (ctx->buf_fill == sizeof(ctx->buf)) {
    kit_sha512_iterate(ctx->h, (uint64_t *)ctx->buf);
    ctx->buf_fill = 0;
  }

  if (ctx->buf_fill > sizeof(ctx->buf) - ((128 / 8) + 1)) {
    ctx->buf[ctx->buf_fill] = 0x80;
    memset(&ctx->buf[ctx->buf_fill + 1], 0, sizeof(ctx->buf) - 1 -
        ctx->buf_fill);
    ctx->processed_bytes[0] += ctx->buf_fill;
    if (ctx->processed_bytes[0] < ctx->buf_fill)
      ctx->processed_bytes[1]++;
    kit_sha512_iterate(ctx->h, (uint64_t *)ctx->buf);

    memset(ctx->buf, 0, sizeof(ctx->buf));
  } else {
    ctx->processed_bytes[0] += ctx->buf_fill;
    if (ctx->processed_bytes[0] < ctx->buf_fill)
      ctx->processed_bytes[1]++;
    ctx->buf[ctx->buf_fill] = 0x80;
    memset(&ctx->buf[ctx->buf_fill + 1], 0, sizeof(ctx->buf) - 1 -
        ctx->buf_fill - ((128 / 8)));
  }

  uint64_t bits[2] = { ctx->processed_bytes[0] << 3,
    (ctx->processed_bytes[1] << 3) + (ctx->processed_bytes[1] >> 59) };
  
  ctx->buf[sizeof(ctx->buf) - 1] = bits[0];
  ctx->buf[sizeof(ctx->buf) - 2] = bits[0] >> 8;
  ctx->buf[sizeof(ctx->buf) - 3] = bits[0] >> 16;
  ctx->buf[sizeof(ctx->buf) - 4] = bits[0] >> 24;
  ctx->buf[sizeof(ctx->buf) - 5] = bits[0] >> 32;
  ctx->buf[sizeof(ctx->buf) - 6] = bits[0] >> 40;
  ctx->buf[sizeof(ctx->buf) - 7] = bits[0] >> 48;
  ctx->buf[sizeof(ctx->buf) - 8] = bits[0] >> 56;
  ctx->buf[sizeof(ctx->buf) - 9] = bits[1];
  ctx->buf[sizeof(ctx->buf) - 10] = bits[1] >> 8;
  ctx->buf[sizeof(ctx->buf) - 11] = bits[1] >> 16;
  ctx->buf[sizeof(ctx->buf) - 12] = bits[1] >> 24;
  ctx->buf[sizeof(ctx->buf) - 13] = bits[1] >> 32;
  ctx->buf[sizeof(ctx->buf) - 14] = bits[1] >> 40;
  ctx->buf[sizeof(ctx->buf) - 15] = bits[1] >> 48;
  ctx->buf[sizeof(ctx->buf) - 16] = bits[1] >> 56;

  kit_sha512_iterate(ctx->h, (uint64_t *)ctx->buf);

  uint64_t out[8];

  out[0] = HTOBE64(ctx->h[0]);
  out[1] = HTOBE64(ctx->h[1]);
  out[2] = HTOBE64(ctx->h[2]);
  out[3] = HTOBE64(ctx->h[3]);
  out[4] = HTOBE64(ctx->h[4]);
  out[5] = HTOBE64(ctx->h[5]);
  if (len) {
    out[6] = HTOBE64(ctx->h[6]);
    out[7] = HTOBE64(ctx->h[7]);
    memcpy(output, out, KIT_SHA512_OUTPUT_SIZE_BYTES);
  } else {
    memcpy(output, out, KIT_SHA384_OUTPUT_SIZE_BYTES);
  }
}

void kit_sha512_finish(kit_sha512_ctx * ctx, uint8_t * output)
{
  kit_sha512_finish_int(ctx, output, 1);
}

void kit_sha384_init(kit_sha512_ctx * ctx)
{
  for (size_t i = 0; i < 8; i++)
    ctx->h[i] = sha384_init_vector[i];

  memset(ctx->buf, 0, sizeof(ctx->buf));
  ctx->buf_fill = 0;
  ctx->processed_bytes[0] = 0;
  ctx->processed_bytes[1] = 0;
}

void kit_sha384_append(kit_sha512_ctx * ctx, const uint8_t * data,
    size_t length)
{
  kit_sha512_append(ctx, data, length);
}

void kit_sha384_finish(kit_sha512_ctx * ctx, uint8_t * output)
{
  kit_sha512_finish_int(ctx, output, 0);
}

void kit_sha384(uint8_t * output, const uint8_t * input, size_t length)
{
  kit_sha512_ctx ctx;
  kit_sha384_init(&ctx);
  kit_sha512_append(&ctx, input, length);
  kit_sha384_finish(&ctx, output);
}

void kit_sha512(uint8_t * output, const uint8_t * input, size_t length)
{
  kit_sha512_ctx ctx;
  kit_sha512_init(&ctx);
  kit_sha512_append(&ctx, input, length);
  kit_sha512_finish(&ctx, output);
}
