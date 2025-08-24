/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include <kitcryptoc/aes.h>
#include <string.h>

#define AES_BLOCK_SIZE 16

static const uint8_t sbox[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const uint8_t Rcon[11] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36 };

#ifdef BIG_ENDIAN
#define HTOBE32(x) (x)

#define BYTE_0(x) (((x) >> 24) & 0xFF)
#define BYTE_1(x) (((x) >> 16) & 0xFF)
#define BYTE_2(x) (((x) >> 8) & 0xFF)
#define BYTE_3(x) ((x) & 0xFF)

#define XOR_0(x, y) x ^= ((y) << 24)
#define XOR_1(x, y) x ^= ((y) << 16)
#define XOR_2(x, y) x ^= ((y) << 8)
#define XOR_3(x, y) x ^= ((y))

#define ADD_0(x, y) x += ((y) << 24)
#define ADD_1(x, y) x += ((y) << 16)
#define ADD_2(x, y) x += ((y) << 8)
#define ADD_3(x, y) x += ((y))
    
#define KEY_INIT_STEP_ROUND temp = ((temp << 8) + (temp >> 24))
#define KEY_INIT_STEP_RCON(x) temp = temp ^ (Rcon[x] << 24)

#elif LITTLE_ENDIAN
#define HTOBE32(x) (((x) >> 24) | (((x) >> 8) & 0xFF00) | \
    (((x) << 8) & 0xFF0000) | (((x) & 0xFF) << 24))

#define BYTE_0(x) ((x) & 0xFF)
#define BYTE_1(x) (((x) >> 8) & 0xFF)
#define BYTE_2(x) (((x) >> 16) & 0xFF)
#define BYTE_3(x) (((x) >> 24) & 0xFF)

#define XOR_0(x, y) x ^= ((y))
#define XOR_1(x, y) x ^= ((y) << 8)
#define XOR_2(x, y) x ^= ((y) << 16)
#define XOR_3(x, y) x ^= ((y) << 24)

#define ADD_0(x, y) x += ((y))
#define ADD_1(x, y) x += ((y) << 8)
#define ADD_2(x, y) x += ((y) << 16)
#define ADD_3(x, y) x += ((y) << 24)

#define KEY_INIT_STEP_ROUND temp = ((temp << 24) + (temp >> 8))
#define KEY_INIT_STEP_RCON(x) temp = temp ^ (Rcon[x])

#else
#error Unknown endian
#endif

#define KEY_INIT_STEP_ASSIGN(i) temp = key->key[i]
#define KEY_INIT_STEP_SBOX temp = (sbox[temp >> 24] << 24) + \
    (sbox[(temp >> 16) & 0xFF] << 16) + (sbox[(temp >> 8) & 0xFF] << 8) + \
    (sbox[temp & 0xFF])
#define KEY_INIT_STEP_END(i, s) key->key[i] = (key->key[s] ^ temp)
    
#ifdef ALG_AES_AARCH64
#include <sys/auxv.h>
#include <asm/hwcap.h>

int kit_aes_cpu_is_supported(void)
{
  return (getauxval(AT_HWCAP) & HWCAP_AES) != 0;
}
#endif

#ifdef ALG_AES_AARCH32
#include <sys/auxv.h>
#include <asm/hwcap.h>

int kit_aes_cpu_is_supported(void)
{
  return (getauxval(AT_HWCAP2) & HWCAP2_AES) != 0;
}
#endif

static void kit_aes_encrypt_block_128(const kit_aes_key * key, uint8_t * output,
    const uint8_t * input);
static void kit_aes_encrypt_block_192(const kit_aes_key * key, uint8_t * output,
    const uint8_t * input);
static void kit_aes_encrypt_block_256(const kit_aes_key * key, uint8_t * output,
    const uint8_t * input);
static void kit_aes_decrypt_block_128(const kit_aes_key * key, uint8_t * output,
    const uint8_t * input);
static void kit_aes_decrypt_block_192(const kit_aes_key * key, uint8_t * output,
    const uint8_t * input);
static void kit_aes_decrypt_block_256(const kit_aes_key * key, uint8_t * output,
    const uint8_t * input);

static void (*kit_aes_encrypt_block_128_func)(const kit_aes_key * key,
    uint8_t * output, const uint8_t * input);
static void (*kit_aes_encrypt_block_192_func)(const kit_aes_key * key,
    uint8_t * output, const uint8_t * input);
static void (*kit_aes_encrypt_block_256_func)(const kit_aes_key * key,
    uint8_t * output, const uint8_t * input);
static void (*kit_aes_decrypt_block_128_func)(const kit_aes_key * key,
    uint8_t * output, const uint8_t * input);
static void (*kit_aes_decrypt_block_192_func)(const kit_aes_key * key,
    uint8_t * output, const uint8_t * input);
static void (*kit_aes_decrypt_block_256_func)(const kit_aes_key * key,
    uint8_t * output, const uint8_t * input);

static void kit_aes_init_ret(void)
{
}

static void kit_aes_init(void);

static void (*kit_aes_init_func)(void) = kit_aes_init;

#if defined(ALG_AES_NI) || defined(ALG_AES_AARCH64) || defined(ALG_AES_AARCH32)
void kit_aes_encrypt_block_128_asm(const kit_aes_key * key, uint8_t * output,
    const uint8_t * input);
void kit_aes_encrypt_block_192_asm(const kit_aes_key * key, uint8_t * output,
    const uint8_t * input);
void kit_aes_encrypt_block_256_asm(const kit_aes_key * key, uint8_t * output,
    const uint8_t * input);
void kit_aes_decrypt_block_128_asm(const kit_aes_key * key, uint8_t * output,
    const uint8_t * input);
void kit_aes_decrypt_block_192_asm(const kit_aes_key * key, uint8_t * output,
    const uint8_t * input);
void kit_aes_decrypt_block_256_asm(const kit_aes_key * key, uint8_t * output,
    const uint8_t * input);

int kit_aes_cpu_is_supported(void);

void kit_aes_init(void)
{
  if (kit_aes_cpu_is_supported()) {
    kit_aes_encrypt_block_128_func = kit_aes_encrypt_block_128_asm;
    kit_aes_encrypt_block_192_func = kit_aes_encrypt_block_192_asm;
    kit_aes_encrypt_block_256_func = kit_aes_encrypt_block_256_asm;
    kit_aes_decrypt_block_128_func = kit_aes_decrypt_block_128_asm;
    kit_aes_decrypt_block_192_func = kit_aes_decrypt_block_192_asm;
    kit_aes_decrypt_block_256_func = kit_aes_decrypt_block_256_asm;
  } else {
    kit_aes_encrypt_block_128_func = kit_aes_encrypt_block_128;
    kit_aes_encrypt_block_192_func = kit_aes_encrypt_block_192;
    kit_aes_encrypt_block_256_func = kit_aes_encrypt_block_256;
    kit_aes_decrypt_block_128_func = kit_aes_decrypt_block_128;
    kit_aes_decrypt_block_192_func = kit_aes_decrypt_block_192;
    kit_aes_decrypt_block_256_func = kit_aes_decrypt_block_256;
  }

  kit_aes_init_func = kit_aes_init_ret;
}

#else

void kit_aes_init(void)
{
  kit_aes_encrypt_block_128_func = kit_aes_encrypt_block_128;
  kit_aes_encrypt_block_192_func = kit_aes_encrypt_block_192;
  kit_aes_encrypt_block_256_func = kit_aes_encrypt_block_256;
  kit_aes_decrypt_block_128_func = kit_aes_decrypt_block_128;
  kit_aes_decrypt_block_192_func = kit_aes_decrypt_block_192;
  kit_aes_decrypt_block_256_func = kit_aes_decrypt_block_256;
  kit_aes_init_func = kit_aes_init_ret;
}

#endif

void kit_aes_init_128(kit_aes_key * key, const uint8_t * source)
{
  kit_aes_init_func();

  memcpy(key->key, source, 16);

  for (unsigned int i = 0; i < 44; i += 4) {
    uint32_t temp;

    KEY_INIT_STEP_ASSIGN(i + 3);
    KEY_INIT_STEP_ROUND;
    KEY_INIT_STEP_SBOX;
    KEY_INIT_STEP_RCON((i / 4) + 1);
    KEY_INIT_STEP_END(i + 4, i);

    KEY_INIT_STEP_ASSIGN(i + 4);
    KEY_INIT_STEP_END(i + 5, i + 1);

    KEY_INIT_STEP_ASSIGN(i + 5);
    KEY_INIT_STEP_END(i + 6, i + 2);

    KEY_INIT_STEP_ASSIGN(i + 6);
    KEY_INIT_STEP_END(i + 7, i + 3);
  }

  key->rounds = 10;
  key->e = kit_aes_encrypt_block_128_func;
  key->d = kit_aes_decrypt_block_128_func;
}

void kit_aes_init_192(kit_aes_key * key, const uint8_t * source)
{
  kit_aes_init_func();

  memcpy(key->key, source, 24);

  for (unsigned int i = 0; i < 66; i += 6) {
    uint32_t temp;

    KEY_INIT_STEP_ASSIGN(i + 5);
    KEY_INIT_STEP_ROUND;
    KEY_INIT_STEP_SBOX;
    KEY_INIT_STEP_RCON((i / 6) + 1);
    KEY_INIT_STEP_END(i + 6, i);

    KEY_INIT_STEP_ASSIGN(i + 6);
    KEY_INIT_STEP_END(i + 7, i + 1);

    KEY_INIT_STEP_ASSIGN(i + 7);
    KEY_INIT_STEP_END(i + 8, i + 2);

    KEY_INIT_STEP_ASSIGN(i + 8);
    KEY_INIT_STEP_END(i + 9, i + 3);

    KEY_INIT_STEP_ASSIGN(i + 9);
    KEY_INIT_STEP_END(i + 10, i + 4);

    KEY_INIT_STEP_ASSIGN(i + 10);
    KEY_INIT_STEP_END(i + 11, i + 5);
  }

  key->rounds = 12;
  key->e = kit_aes_encrypt_block_192_func;
  key->d = kit_aes_decrypt_block_192_func;
}

void kit_aes_init_256(kit_aes_key * key, const uint8_t * source)
{
  kit_aes_init_func();

  memcpy(key->key, source, 32);

  for (unsigned int i = 0; i < 88; i += 8) {
    uint32_t temp;

    KEY_INIT_STEP_ASSIGN(i + 7);
    KEY_INIT_STEP_ROUND;
    KEY_INIT_STEP_SBOX;
    KEY_INIT_STEP_RCON((i / 8) + 1);
    KEY_INIT_STEP_END(i + 8, i);

    KEY_INIT_STEP_ASSIGN(i + 8);
    KEY_INIT_STEP_END(i + 9, i + 1);

    KEY_INIT_STEP_ASSIGN(i + 9);
    KEY_INIT_STEP_END(i + 10, i + 2);

    KEY_INIT_STEP_ASSIGN(i + 10);
    KEY_INIT_STEP_END(i + 11, i + 3);

    KEY_INIT_STEP_ASSIGN(i + 11);
    KEY_INIT_STEP_SBOX;
    KEY_INIT_STEP_END(i + 12, i + 4);

    KEY_INIT_STEP_ASSIGN(i + 12);
    KEY_INIT_STEP_END(i + 13, i + 5);

    KEY_INIT_STEP_ASSIGN(i + 13);
    KEY_INIT_STEP_END(i + 14, i + 6);

    KEY_INIT_STEP_ASSIGN(i + 14);
    KEY_INIT_STEP_END(i + 15, i + 7);
  }

  key->rounds = 14;
  key->e = kit_aes_encrypt_block_256_func;
  key->d = kit_aes_decrypt_block_256_func;
}

#define add_round_key(key_arg, round_arg, data_arg) \
  (data_arg)[0] ^= key_arg->key[round_arg * 4 + 0]; \
  (data_arg)[1] ^= key_arg->key[round_arg * 4 + 1]; \
  (data_arg)[2] ^= key_arg->key[round_arg * 4 + 2]; \
  (data_arg)[3] ^= key_arg->key[round_arg * 4 + 3];

#define sub_bytes(data_arg) \
  (data_arg)[0] = (sbox[(data_arg)[0] >> 24] << 24) + \
      (sbox[((data_arg)[0] >> 16) & 0xFF] << 16) + \
      (sbox[((data_arg)[0] >> 8) & 0xFF] << 8) + \
      (sbox[(data_arg)[0] & 0xFF]); \
  (data_arg)[1] = (sbox[(data_arg)[1] >> 24] << 24) + \
      (sbox[((data_arg)[1] >> 16) & 0xFF] << 16) + \
      (sbox[((data_arg)[1] >> 8) & 0xFF] << 8) + \
      (sbox[(data_arg)[1] & 0xFF]); \
  (data_arg)[2] = (sbox[(data_arg)[2] >> 24] << 24) + \
      (sbox[((data_arg)[2] >> 16) & 0xFF] << 16) + \
      (sbox[((data_arg)[2] >> 8) & 0xFF] << 8) + \
      (sbox[(data_arg)[2] & 0xFF]); \
  (data_arg)[3] = (sbox[(data_arg)[3] >> 24] << 24) + \
      (sbox[((data_arg)[3] >> 16) & 0xFF] << 16) + \
      (sbox[((data_arg)[3] >> 8) & 0xFF] << 8) + \
      (sbox[(data_arg)[3] & 0xFF]);

#define shift_rows(data_arg) \
{ \
  uint32_t tmp; \
  tmp = ((data_arg)[0] ^ (data_arg)[1]) & HTOBE32(0x00FF0000); \
  (data_arg)[0] ^= tmp; \
  (data_arg)[1] ^= tmp; \
  tmp = ((data_arg)[1] ^ (data_arg)[2]) & HTOBE32(0x00FF0000); \
  (data_arg)[1] ^= tmp; \
  (data_arg)[2] ^= tmp; \
  tmp = ((data_arg)[2] ^ (data_arg)[3]) & HTOBE32(0x00FF0000); \
  (data_arg)[2] ^= tmp; \
  (data_arg)[3] ^= tmp; \
  tmp = ((data_arg)[0] ^ (data_arg)[2]) & HTOBE32(0x0000FF00); \
  (data_arg)[0] ^= tmp; \
  (data_arg)[2] ^= tmp; \
  tmp = ((data_arg)[1] ^ (data_arg)[3]) & HTOBE32(0x0000FF00); \
  (data_arg)[1] ^= tmp; \
  (data_arg)[3] ^= tmp; \
  tmp = ((data_arg)[2] ^ (data_arg)[3]) & HTOBE32(0x000000FF); \
  (data_arg)[2] ^= tmp; \
  (data_arg)[3] ^= tmp; \
  tmp = ((data_arg)[1] ^ (data_arg)[2]) & HTOBE32(0x000000FF); \
  (data_arg)[1] ^= tmp; \
  (data_arg)[2] ^= tmp; \
  tmp = ((data_arg)[0] ^ (data_arg)[1]) & HTOBE32(0x000000FF); \
  (data_arg)[0] ^= tmp; \
  (data_arg)[1] ^= tmp; \
}

#define xtime(x) ((uint8_t)(((x) << 1) ^ ((((x) >> 7) & 1) * 0x1B)))

#define mix_columns(data_arg) \
{ \
  uint8_t a, b, c; \
  a = BYTE_0((data_arg)[0]); \
  b = a ^ BYTE_1((data_arg)[0]); \
  c = b ^ BYTE_2((data_arg)[0]) ^ BYTE_3((data_arg)[0]); \
  XOR_0((data_arg)[0], xtime(b) ^ c); \
  b = BYTE_1((data_arg)[0]) ^ BYTE_2((data_arg)[0]); \
  XOR_1((data_arg)[0], (xtime(b) ^ c)); \
  b = BYTE_2((data_arg)[0]) ^ BYTE_3((data_arg)[0]); \
  XOR_2((data_arg)[0], (xtime(b) ^ c)); \
  b = a ^ BYTE_3((data_arg)[0]); \
  XOR_3((data_arg)[0], (xtime(b) ^ c)); \
  a = BYTE_0((data_arg)[1]); \
  b = a ^ BYTE_1((data_arg)[1]); \
  c = b ^ BYTE_2((data_arg)[1]) ^ BYTE_3((data_arg)[1]); \
  XOR_0((data_arg)[1], xtime(b) ^ c); \
  b = BYTE_1((data_arg)[1]) ^ BYTE_2((data_arg)[1]); \
  XOR_1((data_arg)[1], (xtime(b) ^ c)); \
  b = BYTE_2((data_arg)[1]) ^ BYTE_3((data_arg)[1]); \
  XOR_2((data_arg)[1], (xtime(b) ^ c)); \
  b = a ^ BYTE_3((data_arg)[1]); \
  XOR_3((data_arg)[1], (xtime(b) ^ c)); \
  a = BYTE_0((data_arg)[2]); \
  b = a ^ BYTE_1((data_arg)[2]); \
  c = b ^ BYTE_2((data_arg)[2]) ^ BYTE_3((data_arg)[2]); \
  XOR_0((data_arg)[2], xtime(b) ^ c); \
  b = BYTE_1((data_arg)[2]) ^ BYTE_2((data_arg)[2]); \
  XOR_1((data_arg)[2], (xtime(b) ^ c)); \
  b = BYTE_2((data_arg)[2]) ^ BYTE_3((data_arg)[2]); \
  XOR_2((data_arg)[2], (xtime(b) ^ c)); \
  b = a ^ BYTE_3((data_arg)[2]); \
  XOR_3((data_arg)[2], (xtime(b) ^ c)); \
  a = BYTE_0((data_arg)[3]); \
  b = a ^ BYTE_1((data_arg)[3]); \
  c = b ^ BYTE_2((data_arg)[3]) ^ BYTE_3((data_arg)[3]); \
  XOR_0((data_arg)[3], xtime(b) ^ c); \
  b = BYTE_1((data_arg)[3]) ^ BYTE_2((data_arg)[3]); \
  XOR_1((data_arg)[3], (xtime(b) ^ c)); \
  b = BYTE_2((data_arg)[3]) ^ BYTE_3((data_arg)[3]); \
  XOR_2((data_arg)[3], (xtime(b) ^ c)); \
  b = a ^ BYTE_3((data_arg)[3]); \
  XOR_3((data_arg)[3], (xtime(b) ^ c)); \
}

#define multiply(a, b) \
  ((((b & 1) * a) ^ \
    ((b >> 1 & 1) * xtime(a)) ^ \
    ((b >> 2 & 1) * xtime(xtime(a))) ^ \
    ((b >> 3 & 1) * xtime(xtime(xtime(a)))) ^ \
    ((b >> 4 & 1) * xtime(xtime(xtime(xtime(a)))))))

#define inv_mix_columns(data_arg) \
{ \
  uint8_t a, b, c, d; \
  uint32_t e; \
  a = BYTE_0((data_arg)[0]); \
  b = BYTE_1((data_arg)[0]); \
  c = BYTE_2((data_arg)[0]); \
  d = BYTE_3((data_arg)[0]); \
  e = 0; \
  ADD_0(e, multiply(a, 0x0E) ^ multiply(b, 0x0B) ^ multiply(c, 0x0D) ^ \
      multiply(d, 0x09)); \
  ADD_1(e, (multiply(a, 0x09) ^ multiply(b, 0x0E) ^ multiply(c, 0x0B) ^ \
      multiply(d, 0x0D))); \
  ADD_2(e, (multiply(a, 0x0D) ^ multiply(b, 0x09) ^ multiply(c, 0x0E) ^ \
      multiply(d, 0x0B))); \
  ADD_3(e, (multiply(a, 0x0B) ^ multiply(b, 0x0D) ^ multiply(c, 0x09) ^ \
      multiply(d, 0x0E))); \
  (data_arg)[0] = e; \
  a = BYTE_0((data_arg)[1]); \
  b = BYTE_1((data_arg)[1]); \
  c = BYTE_2((data_arg)[1]); \
  d = BYTE_3((data_arg)[1]); \
  e = 0; \
  ADD_0(e, multiply(a, 0x0E) ^ multiply(b, 0x0B) ^ multiply(c, 0x0D) ^ \
      multiply(d, 0x09)); \
  ADD_1(e, (multiply(a, 0x09) ^ multiply(b, 0x0E) ^ multiply(c, 0x0B) ^ \
      multiply(d, 0x0D))); \
  ADD_2(e, (multiply(a, 0x0D) ^ multiply(b, 0x09) ^ multiply(c, 0x0E) ^ \
      multiply(d, 0x0B))); \
  ADD_3(e, (multiply(a, 0x0B) ^ multiply(b, 0x0D) ^ multiply(c, 0x09) ^ \
      multiply(d, 0x0E))); \
  (data_arg)[1] = e; \
  a = BYTE_0((data_arg)[2]); \
  b = BYTE_1((data_arg)[2]); \
  c = BYTE_2((data_arg)[2]); \
  d = BYTE_3((data_arg)[2]); \
  e = 0; \
  ADD_0(e, multiply(a, 0x0E) ^ multiply(b, 0x0B) ^ multiply(c, 0x0D) ^ \
      multiply(d, 0x09)); \
  ADD_1(e, (multiply(a, 0x09) ^ multiply(b, 0x0E) ^ multiply(c, 0x0B) ^ \
      multiply(d, 0x0D))); \
  ADD_2(e, (multiply(a, 0x0D) ^ multiply(b, 0x09) ^ multiply(c, 0x0E) ^ \
      multiply(d, 0x0B))); \
  ADD_3(e, (multiply(a, 0x0B) ^ multiply(b, 0x0D) ^ multiply(c, 0x09) ^ \
      multiply(d, 0x0E))); \
  (data_arg)[2] = e; \
  a = BYTE_0((data_arg)[3]); \
  b = BYTE_1((data_arg)[3]); \
  c = BYTE_2((data_arg)[3]); \
  d = BYTE_3((data_arg)[3]); \
  e = 0; \
  ADD_0(e, multiply(a, 0x0E) ^ multiply(b, 0x0B) ^ multiply(c, 0x0D) ^ \
      multiply(d, 0x09)); \
  ADD_1(e, (multiply(a, 0x09) ^ multiply(b, 0x0E) ^ multiply(c, 0x0B) ^ \
      multiply(d, 0x0D))); \
  ADD_2(e, (multiply(a, 0x0D) ^ multiply(b, 0x09) ^ multiply(c, 0x0E) ^ \
      multiply(d, 0x0B))); \
  ADD_3(e, (multiply(a, 0x0B) ^ multiply(b, 0x0D) ^ multiply(c, 0x09) ^ \
      multiply(d, 0x0E))); \
  (data_arg)[3] = e; \
}

#define inv_sub_bytes(data_arg) \
  (data_arg)[0] = (rsbox[(data_arg)[0] >> 24] << 24) + (rsbox[((data_arg)[0] >> 16) & 0xFF] << 16) + \
      (rsbox[((data_arg)[0] >> 8) & 0xFF] << 8) + (rsbox[(data_arg)[0] & 0xFF]); \
  (data_arg)[1] = (rsbox[(data_arg)[1] >> 24] << 24) + (rsbox[((data_arg)[1] >> 16) & 0xFF] << 16) + \
      (rsbox[((data_arg)[1] >> 8) & 0xFF] << 8) + (rsbox[(data_arg)[1] & 0xFF]); \
  (data_arg)[2] = (rsbox[(data_arg)[2] >> 24] << 24) + (rsbox[((data_arg)[2] >> 16) & 0xFF] << 16) + \
      (rsbox[((data_arg)[2] >> 8) & 0xFF] << 8) + (rsbox[(data_arg)[2] & 0xFF]); \
  (data_arg)[3] = (rsbox[(data_arg)[3] >> 24] << 24) + (rsbox[((data_arg)[3] >> 16) & 0xFF] << 16) + \
      (rsbox[((data_arg)[3] >> 8) & 0xFF] << 8) + (rsbox[(data_arg)[3] & 0xFF]);

#define inv_shift_rows(data_arg) \
{ \
  uint32_t tmp; \
  tmp = ((data_arg)[2] ^ (data_arg)[3]) & HTOBE32(0x00FF0000); \
  (data_arg)[2] ^= tmp; \
  (data_arg)[3] ^= tmp; \
  tmp = ((data_arg)[1] ^ (data_arg)[2]) & HTOBE32(0x00FF0000); \
  (data_arg)[1] ^= tmp; \
  (data_arg)[2] ^= tmp; \
  tmp = ((data_arg)[0] ^ (data_arg)[1]) & HTOBE32(0x00FF0000); \
  (data_arg)[0] ^= tmp; \
  (data_arg)[1] ^= tmp; \
  tmp = ((data_arg)[1] ^ (data_arg)[3]) & HTOBE32(0x0000FF00); \
  (data_arg)[1] ^= tmp; \
  (data_arg)[3] ^= tmp; \
  tmp = ((data_arg)[0] ^ (data_arg)[2]) & HTOBE32(0x0000FF00); \
  (data_arg)[0] ^= tmp; \
  (data_arg)[2] ^= tmp; \
  tmp = ((data_arg)[0] ^ (data_arg)[1]) & HTOBE32(0x000000FF); \
  (data_arg)[0] ^= tmp; \
  (data_arg)[1] ^= tmp; \
  tmp = ((data_arg)[1] ^ (data_arg)[2]) & HTOBE32(0x000000FF); \
  (data_arg)[1] ^= tmp; \
  (data_arg)[2] ^= tmp; \
  tmp = ((data_arg)[2] ^ (data_arg)[3]) & HTOBE32(0x000000FF); \
  (data_arg)[2] ^= tmp; \
  (data_arg)[3] ^= tmp; \
}

void kit_aes_encrypt_block_128(const kit_aes_key * key, uint8_t * output,
    const uint8_t * input)
{
  uint32_t block[4];
  memcpy(block, input, AES_BLOCK_SIZE);

  add_round_key(key, 0, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 1, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 2, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 3, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 4, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 5, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 6, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 7, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 8, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 9, block);
  sub_bytes(block);
  shift_rows(block);

  add_round_key(key, 10, block);

  memcpy(output, block, AES_BLOCK_SIZE);
}

void kit_aes_encrypt_block_192(const kit_aes_key * key, uint8_t * output,
    const uint8_t * input)
{
  uint32_t block[4];
  memcpy(block, input, AES_BLOCK_SIZE);

  add_round_key(key, 0, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 1, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 2, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 3, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 4, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 5, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 6, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 7, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 8, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 9, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 10, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 11, block);
  sub_bytes(block);
  shift_rows(block);

  add_round_key(key, 12, block);

  memcpy(output, block, AES_BLOCK_SIZE);
}

void kit_aes_encrypt_block_256(const kit_aes_key * key, uint8_t * output,
    const uint8_t * input)
{
  uint32_t block[4];
  memcpy(block, input, AES_BLOCK_SIZE);

  add_round_key(key, 0, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 1, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 2, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 3, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 4, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 5, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 6, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 7, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 8, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 9, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 10, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 11, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 12, block);
  sub_bytes(block);
  shift_rows(block);

  mix_columns(block);
  add_round_key(key, 13, block);
  sub_bytes(block);
  shift_rows(block);

  add_round_key(key, 14, block);

  memcpy(output, block, AES_BLOCK_SIZE);
}

void kit_aes_decrypt_block_128(const kit_aes_key * key, uint8_t * output,
    const uint8_t * input)
{
  uint32_t block[4];
  memcpy(block, input, AES_BLOCK_SIZE);

  add_round_key(key, 10, block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 9, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 8, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 7, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 6, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 5, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 4, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 3, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 2, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 1, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 0, block);

  memcpy(output, block, AES_BLOCK_SIZE);
}

void kit_aes_decrypt_block_192(const kit_aes_key * key, uint8_t * output,
    const uint8_t * input)
{
  uint32_t block[4];
  memcpy(block, input, AES_BLOCK_SIZE);

  add_round_key(key, 12, block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 11, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 10, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 9, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 8, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 7, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 6, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 5, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 4, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 3, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 2, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 1, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 0, block);

  memcpy(output, block, AES_BLOCK_SIZE);
}

void kit_aes_decrypt_block_256(const kit_aes_key * key, uint8_t * output,
    const uint8_t * input)
{
  uint32_t block[4];
  memcpy(block, input, AES_BLOCK_SIZE);

  add_round_key(key, 14, block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 13, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 12, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 11, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 10, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 9, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 8, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 7, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 6, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 5, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 4, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 3, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 2, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 1, block);

  inv_mix_columns(block);
  inv_shift_rows(block);
  inv_sub_bytes(block);
  add_round_key(key, 0, block);

  memcpy(output, block, AES_BLOCK_SIZE);
}

void kit_aes_encrypt_block(const kit_aes_key * key, uint8_t * output,
    const uint8_t * input)
{
  key->e(key, output, input);
}

void kit_aes_decrypt_block(const kit_aes_key * key, uint8_t * output,
    const uint8_t * input)
{
  key->d(key, output, input);
}
