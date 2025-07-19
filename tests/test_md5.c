/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include <kitcryptoc/md5.h>
#include <stdio.h>
#include <string.h>

const uint8_t hash_md5_1[KIT_MD5_OUTPUT_SIZE_BYTES] = {
  0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec,
  0xf8, 0x42, 0x7e
};

const uint8_t hash_md5_2[KIT_MD5_OUTPUT_SIZE_BYTES] = {
  0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8, 0x31, 0xc3, 0x99, 0xe2, 0x69,
  0x77, 0x26, 0x61
};

const char md5_input_2[] = "a";

const uint8_t hash_md5_3[KIT_MD5_OUTPUT_SIZE_BYTES] = {
  0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28,
  0xe1, 0x7f, 0x72
};

const char md5_input_3[] = "abc";

const uint8_t hash_md5_4[KIT_MD5_OUTPUT_SIZE_BYTES] = {
  0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d, 0x52, 0x5a, 0x2f, 0x31, 0xaa,
  0xf1, 0x61, 0xd0
};

const char md5_input_4[] = "message digest";

const uint8_t hash_md5_5[KIT_MD5_OUTPUT_SIZE_BYTES] = {
  0xc3, 0xfc, 0xd3, 0xd7, 0x61, 0x92, 0xe4, 0x00, 0x7d, 0xfb, 0x49, 0x6c, 0xca,
  0x67, 0xe1, 0x3b
};

const char md5_input_5[] = "abcdefghijklmnopqrstuvwxyz";

const uint8_t hash_md5_6[KIT_MD5_OUTPUT_SIZE_BYTES] = {
  0xd1, 0x74, 0xab, 0x98, 0xd2, 0x77, 0xd9, 0xf5, 0xa5, 0x61, 0x1c, 0x2c, 0x9f,
  0x41, 0x9d, 0x9f
};

const char md5_input_6[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

const uint8_t hash_md5_7[KIT_MD5_OUTPUT_SIZE_BYTES] = {
  0x57, 0xed, 0xf4, 0xa2, 0x2b, 0xe3, 0xc9, 0x55, 0xac, 0x49, 0xda, 0x2e, 0x21,
  0x07, 0xb6, 0x7a
};

const char md5_input_7[] =
  "123456789012345678901234567890123456789012345678901234567890123456"
  "78901234567890";

int test_md5_1(void)
{
  uint8_t hash[KIT_MD5_OUTPUT_SIZE_BYTES];
  kit_md5(hash, "", 0);
  int r = memcmp(hash, hash_md5_1, sizeof(hash_md5_1));
  if (r) {
    fprintf(stderr, "1. Invalid MD5 result from empty input\n");
  }
  return r;
}

int test_md5_2(void)
{
  uint8_t hash[KIT_MD5_OUTPUT_SIZE_BYTES];
  kit_md5(hash, md5_input_2, sizeof(md5_input_2) - 1);
  int r = memcmp(hash, hash_md5_2, sizeof(hash_md5_2));
  if (r) {
    fprintf(stderr, "2. Invalid MD5 result from \"%s\" input\n", md5_input_2);
  }
  return r;
}

int test_md5_3(void)
{
  uint8_t hash[KIT_MD5_OUTPUT_SIZE_BYTES];
  kit_md5(hash, md5_input_3, sizeof(md5_input_3) - 1);
  int r = memcmp(hash, hash_md5_3, sizeof(hash_md5_3));
  if (r) {
    fprintf(stderr, "3. Invalid MD5 result from \"%s\" input\n", md5_input_3);
  }
  return r;
}

int test_md5_4(void)
{
  uint8_t hash[KIT_MD5_OUTPUT_SIZE_BYTES];
  kit_md5(hash, md5_input_4, sizeof(md5_input_4) - 1);
  int r = memcmp(hash, hash_md5_4, sizeof(hash_md5_4));
  if (r) {
    fprintf(stderr, "4. Invalid MD5 result from \"%s\" input\n", md5_input_4);
  }
  return r;
}

int test_md5_5(void)
{
  uint8_t hash[KIT_MD5_OUTPUT_SIZE_BYTES];
  kit_md5(hash, md5_input_5, sizeof(md5_input_5) - 1);
  int r = memcmp(hash, hash_md5_5, sizeof(hash_md5_5));
  if (r) {
    fprintf(stderr, "5. Invalid MD5 result from \"%s\" input\n", md5_input_5);
  }
  return r;
}

int test_md5_6(void)
{
  uint8_t hash[KIT_MD5_OUTPUT_SIZE_BYTES];
  kit_md5(hash, md5_input_6, sizeof(md5_input_6) - 1);
  int r = memcmp(hash, hash_md5_6, sizeof(hash_md5_6));
  if (r) {
    fprintf(stderr, "6. Invalid MD5 result from \"%s\" input\n", md5_input_6);
  }
  return r;
}

int test_md5_7(void)
{
  uint8_t hash[KIT_MD5_OUTPUT_SIZE_BYTES];
  kit_md5(hash, md5_input_7, sizeof(md5_input_7) - 1);
  int r = memcmp(hash, hash_md5_7, sizeof(hash_md5_7));
  if (r) {
    fprintf(stderr, "7. Invalid MD5 result from \"%s\" input\n", md5_input_7);
  }
  return r;
}

int test_md5_8(void)
{
  uint8_t hash[KIT_MD5_OUTPUT_SIZE_BYTES];
  kit_md5_ctx ctx;

  kit_md5_init(&ctx);
  for (size_t i = 0; i < sizeof(md5_input_7) - 1; i++)
    kit_md5_append(&ctx, &md5_input_7[i], 1);
  kit_md5_finish(&ctx, hash);

  int r = memcmp(hash, hash_md5_7, sizeof(hash_md5_7));
  if (r) {
    fprintf(stderr, "8. Invalid MD5 result from \"%s\" input\n", md5_input_7);
  }
  return r;
}

int test_md5_9(void)
{
  uint8_t hash[KIT_MD5_OUTPUT_SIZE_BYTES + 2];
  kit_md5(hash + 2, "", 0);
  int r = memcmp(hash + 2, hash_md5_1, sizeof(hash_md5_1));
  if (r) {
    fprintf(stderr, "9. Invalid MD5 result from empty input\n");
  }
  return r;
}

int main(int argc, char * argv[])
{
  if (test_md5_1())
    return 1;
  if (test_md5_2())
    return 1;
  if (test_md5_3())
    return 1;
  if (test_md5_4())
    return 1;
  if (test_md5_5())
    return 1;
  if (test_md5_6())
    return 1;
  if (test_md5_7())
    return 1;
  if (test_md5_8())
    return 1;
  if (test_md5_9())
    return 1;

  return 0;
}
