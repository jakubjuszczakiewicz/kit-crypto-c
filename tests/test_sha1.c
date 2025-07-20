/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include <kitcryptoc/sha1.h>
#include <stdio.h>
#include <string.h>

const uint8_t hash_sha1_1[KIT_SHA1_OUTPUT_SIZE_BYTES] = {
  0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95,
  0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
};


const uint8_t hash_sha1_2[KIT_SHA1_OUTPUT_SIZE_BYTES] = {
  0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb,
  0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12
};

const char sha1_input_2[] = "The quick brown fox jumps over the lazy dog";

const uint8_t hash_sha1_3[KIT_SHA1_OUTPUT_SIZE_BYTES] = {
  0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78,
  0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
};

const char sha1_input_3[] = "abc";


const uint8_t hash_sha1_4[KIT_SHA1_OUTPUT_SIZE_BYTES] = {
  0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1, 0xf9,
  0x51, 0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1
};

const char sha1_input_4[] = "abcdbcdecdefdefgefghfghighijhi" \
  "jkijkljklmklmnlmnomnopnopq";

const uint8_t hash_sha1_5[KIT_SHA1_OUTPUT_SIZE_BYTES] = {
  0x34, 0xaa, 0x97, 0x3c, 0xd4, 0xc4, 0xda, 0xa4, 0xf6, 0x1e, 0xeb, 0x2b, 0xdb,
  0xad, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6f
};

const char sha1_input_5[] = "a";

const uint8_t hash_sha1_6[KIT_SHA1_OUTPUT_SIZE_BYTES] = {
  0xde, 0xa3, 0x56, 0xa2, 0xcd, 0xdd, 0x90, 0xc7, 0xa7, 0xec, 0xed, 0xc5, 0xeb,
  0xb5, 0x63, 0x93, 0x4f, 0x46, 0x04, 0x52
};

const char sha1_input_6[] = {
  "01234567012345670123456701234567"
  "01234567012345670123456701234567"
};

const char sha1_input_7[] = "  abcdbcdecdefdefgefghfghighijhi" \
  "jkijkljklmklmnlmnomnopnopq";

int test_sha1_1(void)
{
  uint8_t hash[KIT_SHA1_OUTPUT_SIZE_BYTES];
  kit_sha1(hash, "", 0);
  int r = memcmp(hash, hash_sha1_1, sizeof(hash_sha1_1));
  if (r) {
    fprintf(stderr, "1. Invalid SHA1 result from empty input\n");
  }
  return r;
}

int test_sha1_2(void)
{
  uint8_t hash[KIT_SHA1_OUTPUT_SIZE_BYTES];
  kit_sha1(hash, sha1_input_2, sizeof(sha1_input_2) - 1);
  int r = memcmp(hash, hash_sha1_2, sizeof(hash_sha1_2));
  if (r) {
    fprintf(stderr, "2. Invalid SHA1 result from \"%s\" input\n", sha1_input_2);
  }
  return r;
}

int test_sha1_3(void)
{
  uint8_t hash[KIT_SHA1_OUTPUT_SIZE_BYTES];
  kit_sha1(hash, sha1_input_3, sizeof(sha1_input_3) - 1);
  int r = memcmp(hash, hash_sha1_3, sizeof(hash_sha1_3));
  if (r) {
    fprintf(stderr, "3. Invalid SHA1 result from \"%s\" input\n", sha1_input_3);
  }
  return r;
}

int test_sha1_4(void)
{
  uint8_t hash[KIT_SHA1_OUTPUT_SIZE_BYTES];
  kit_sha1(hash, sha1_input_4, sizeof(sha1_input_4) - 1);
  int r = memcmp(hash, hash_sha1_4, sizeof(hash_sha1_4));
  if (r) {
    fprintf(stderr, "4. Invalid SHA1 result from \"%s\" input\n", sha1_input_4);
  }
  return r;
}

int test_sha1_5(void)
{
  uint8_t hash[KIT_SHA1_OUTPUT_SIZE_BYTES];
  kit_sha1_ctx ctx;
  kit_sha1_init(&ctx);

  for (uint32_t i = 0; i < 1000000; i++) {
    kit_sha1_append(&ctx, sha1_input_5, sizeof(sha1_input_5) - 1);
  }
  kit_sha1_finish(&ctx, hash);

  int r = memcmp(hash, hash_sha1_5, sizeof(hash_sha1_5));
  if (r) {
    fprintf(stderr, "5. Invalid SHA1 result from \"%s\" 1000000 times input\n",
        sha1_input_5);  }
  return r;
}

int test_sha1_6(void)
{
  uint8_t hash[KIT_SHA1_OUTPUT_SIZE_BYTES];
  kit_sha1_ctx ctx;
  kit_sha1_init(&ctx);

  for (uint32_t i = 0; i < 10; i++) {
    kit_sha1_append(&ctx, sha1_input_6, sizeof(sha1_input_6) - 1);
  }
  kit_sha1_finish(&ctx, hash);

  int r = memcmp(hash, hash_sha1_6, sizeof(hash_sha1_6));
  if (r) {
    fprintf(stderr, "5. Invalid SHA1 result from \"%s\" 10 times input\n",
        sha1_input_6 + 1);
  }
  return r;
}

int test_sha1_7(void)
{
  uint8_t hash[KIT_SHA1_OUTPUT_SIZE_BYTES + 2];
  kit_sha1(hash + 2, "", 0);
  int r = memcmp(hash + 2, hash_sha1_1, sizeof(hash_sha1_1));
  if (r) {
    fprintf(stderr, "7. Invalid SHA1 result from empty input\n");
  }
  return r;
}

int test_sha1_8(void)
{
  uint8_t hash[KIT_SHA1_OUTPUT_SIZE_BYTES];
  kit_sha1(hash, sha1_input_7 + 2, sizeof(sha1_input_7) - 3);
  int r = memcmp(hash, hash_sha1_4, sizeof(hash_sha1_4));
  if (r) {
    fprintf(stderr, "8. Invalid SHA1 result from \"%s\" input\n",
        sha1_input_4);
  }
  return r;
}

int main(int argc, char * argv[])
{
  if (test_sha1_1())
    return 1;
  if (test_sha1_2())
    return 1;
  if (test_sha1_3())
    return 1;
  if (test_sha1_4())
    return 1;
  if (test_sha1_5())
    return 1;
  if (test_sha1_6())
    return 1;
  if (test_sha1_7())
    return 1;
  if (test_sha1_8())
    return 1;

  return 0;
}
