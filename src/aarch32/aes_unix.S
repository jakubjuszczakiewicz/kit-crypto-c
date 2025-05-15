.text

.global kit_aes_encrypt_block_128_asm
.global kit_aes_encrypt_block_192_asm
.global kit_aes_encrypt_block_256_asm
.global kit_aes_decrypt_block_128_asm
.global kit_aes_decrypt_block_192_asm
.global kit_aes_decrypt_block_256_asm

.p2align 4

.macro preserve_caller_registers
  vpush {q4, q5}
  vpush {q6, q7}
.endm

.macro restore_caller_registers
  vpop {q6, q7}
  vpop {q4, q5}
.endm

.p2align 4
kit_aes_encrypt_block_128_asm:
  preserve_caller_registers

  vld1.u8 {q0}, [r2]!
  vld1.u8 {q1, q2}, [r0]!
  vld1.u8 {q3, q4}, [r0]!
  vld1.u8 {q5, q6}, [r0]!
  vld1.u8 {q7, q8}, [r0]!
  vld1.u8 {q9, q10}, [r0]!
  vld1.u8 {q11}, [r0]!

  aese.8  q0, q1
  aesmc.8 q0, q0
  aese.8  q0, q2
  aesmc.8 q0, q0
  aese.8  q0, q3
  aesmc.8 q0, q0
  aese.8  q0, q4
  aesmc.8 q0, q0
  aese.8  q0, q5
  aesmc.8 q0, q0
  aese.8  q0, q6
  aesmc.8 q0, q0
  aese.8  q0, q7
  aesmc.8 q0, q0
  aese.8  q0, q8
  aesmc.8 q0, q0
  aese.8  q0, q9
  aesmc.8 q0, q0
  aese.8  q0, q10
  veor.8  q0, q0, q11

  vst1.u8 {q0},[r1]

  restore_caller_registers
  bx lr

.p2align 4
kit_aes_encrypt_block_192_asm:
  preserve_caller_registers

  vld1.u8 {q0}, [r2]!
  vld1.u8 {q1, q2}, [r0]!
  vld1.u8 {q3, q4}, [r0]!
  vld1.u8 {q5, q6}, [r0]!
  vld1.u8 {q7, q8}, [r0]!
  vld1.u8 {q9, q10}, [r0]!
  vld1.u8 {q11, q12}, [r0]!
  vld1.u8 {q13}, [r0]!

  aese.8  q0, q1
  aesmc.8 q0, q0
  aese.8  q0, q2
  aesmc.8 q0, q0
  aese.8  q0, q3
  aesmc.8 q0, q0
  aese.8  q0, q4
  aesmc.8 q0, q0
  aese.8  q0, q5
  aesmc.8 q0, q0
  aese.8  q0, q6
  aesmc.8 q0, q0
  aese.8  q0, q7
  aesmc.8 q0, q0
  aese.8  q0, q8
  aesmc.8 q0, q0
  aese.8  q0, q9
  aesmc.8 q0, q0
  aese.8  q0, q10
  aesmc.8 q0, q0
  aese.8  q0, q11
  aesmc.8 q0, q0
  aese.8  q0, q12
  veor.8  q0, q0, q13

  vst1.u8 {q0},[r1]

  restore_caller_registers
  bx lr

.p2align 4
kit_aes_encrypt_block_256_asm:
  preserve_caller_registers

  vld1.u8 {q0}, [r2]!
  vld1.u8 {q1, q2}, [r0]!
  vld1.u8 {q3, q4}, [r0]!
  vld1.u8 {q5, q6}, [r0]!
  vld1.u8 {q7, q8}, [r0]!
  vld1.u8 {q9, q10}, [r0]!
  vld1.u8 {q11, q12}, [r0]!
  vld1.u8 {q13, q14}, [r0]!
  vld1.u8 {q15}, [r0]!

  aese.8  q0, q1
  aesmc.8 q0, q0
  aese.8  q0, q2
  aesmc.8 q0, q0
  aese.8  q0, q3
  aesmc.8 q0, q0
  aese.8  q0, q4
  aesmc.8 q0, q0
  aese.8  q0, q5
  aesmc.8 q0, q0
  aese.8  q0, q6
  aesmc.8 q0, q0
  aese.8  q0, q7
  aesmc.8 q0, q0
  aese.8  q0, q8
  aesmc.8 q0, q0
  aese.8  q0, q9
  aesmc.8 q0, q0
  aese.8  q0, q10
  aesmc.8 q0, q0
  aese.8  q0, q11
  aesmc.8 q0, q0
  aese.8  q0, q12
  aesmc.8 q0, q0
  aese.8  q0, q13
  aesmc.8 q0, q0
  aese.8  q0, q14
  veor.8  q0, q0, q15

  vst1.u8 {q0},[r1]

  restore_caller_registers
  bx lr

.p2align 4
kit_aes_decrypt_block_128_asm:
  preserve_caller_registers

  vld1.u8 {q0}, [r2]!
  vld1.u8 {q1, q2}, [r0]!
  vld1.u8 {q3, q4}, [r0]!
  vld1.u8 {q5, q6}, [r0]!
  vld1.u8 {q7, q8}, [r0]!
  vld1.u8 {q9, q10}, [r0]!
  vld1.u8 {q11}, [r0]!

  aesd.8  q0, q11
  veor.8  q0, q0, q10
  aesimc.8 q0, q0
  veor.8  q0, q0, q9
  aesd.8  q0, q9
  veor.8  q0, q0, q9
  aesimc.8 q0, q0
  veor.8  q0, q0, q8
  aesd.8  q0, q8
  veor.8  q0, q0, q8
  aesimc.8 q0, q0
  veor.8  q0, q0, q7
  aesd.8  q0, q7
  veor.8  q0, q0, q7
  aesimc.8 q0, q0
  veor.8  q0, q0, q6
  aesd.8  q0, q6
  veor.8  q0, q0, q6
  aesimc.8 q0, q0
  veor.8  q0, q0, q5
  aesd.8  q0, q5
  veor.8  q0, q0, q5
  aesimc.8 q0, q0
  veor.8  q0, q0, q4
  aesd.8  q0, q4
  veor.8  q0, q0, q4
  aesimc.8 q0, q0
  veor.8  q0, q0, q3
  aesd.8  q0, q3
  veor.8  q0, q0, q3
  aesimc.8 q0, q0
  veor.8  q0, q0, q2
  aesd.8  q0, q2
  veor.8  q0, q0, q2
  aesimc.8 q0, q0
  veor.8  q0, q0, q1
  aesd.8  q0, q1
  veor.8  q0, q0, q1

  vst1.u8 {q0},[r1]

  restore_caller_registers
  bx lr

.p2align 4
kit_aes_decrypt_block_192_asm:
  preserve_caller_registers

  vld1.u8 {q0}, [r2]!
  vld1.u8 {q1, q2}, [r0]!
  vld1.u8 {q3, q4}, [r0]!
  vld1.u8 {q5, q6}, [r0]!
  vld1.u8 {q7, q8}, [r0]!
  vld1.u8 {q9, q10}, [r0]!
  vld1.u8 {q11, q12}, [r0]!
  vld1.u8 {q13}, [r0]!

  aesd.8  q0, q13
  veor.8  q0, q0, q12
  aesimc.8 q0, q0
  veor.8  q0, q0, q11
  aesd.8  q0, q11
  veor.8  q0, q0, q11
  aesimc.8 q0, q0
  veor.8  q0, q0, q10
  aesd.8  q0, q10
  veor.8  q0, q0, q10
  aesimc.8 q0, q0
  veor.8  q0, q0, q9
  aesd.8  q0, q9
  veor.8  q0, q0, q9
  aesimc.8 q0, q0
  veor.8  q0, q0, q8
  aesd.8  q0, q8
  veor.8  q0, q0, q8
  aesimc.8 q0, q0
  veor.8  q0, q0, q7
  aesd.8  q0, q7
  veor.8  q0, q0, q7
  aesimc.8 q0, q0
  veor.8  q0, q0, q6
  aesd.8  q0, q6
  veor.8  q0, q0, q6
  aesimc.8 q0, q0
  veor.8  q0, q0, q5
  aesd.8  q0, q5
  veor.8  q0, q0, q5
  aesimc.8 q0, q0
  veor.8  q0, q0, q4
  aesd.8  q0, q4
  veor.8  q0, q0, q4
  aesimc.8 q0, q0
  veor.8  q0, q0, q3
  aesd.8  q0, q3
  veor.8  q0, q0, q3
  aesimc.8 q0, q0
  veor.8  q0, q0, q2
  aesd.8  q0, q2
  veor.8  q0, q0, q2
  aesimc.8 q0, q0
  veor.8  q0, q0, q1
  aesd.8  q0, q1
  veor.8  q0, q0, q1

  vst1.u8 {q0},[r1]

  restore_caller_registers
  bx lr

.p2align 4
kit_aes_decrypt_block_256_asm:
  preserve_caller_registers

  vld1.u8 {q0}, [r2]!
  vld1.u8 {q1, q2}, [r0]!
  vld1.u8 {q3, q4}, [r0]!
  vld1.u8 {q5, q6}, [r0]!
  vld1.u8 {q7, q8}, [r0]!
  vld1.u8 {q9, q10}, [r0]!
  vld1.u8 {q11, q12}, [r0]!
  vld1.u8 {q13, q14}, [r0]!
  vld1.u8 {q15}, [r0]!

  aesd.8  q0, q15
  veor.8  q0, q0, q14
  aesimc.8 q0, q0
  veor.8  q0, q0, q13
  aesd.8  q0, q13
  veor.8  q0, q0, q13
  aesimc.8 q0, q0
  veor.8  q0, q0, q12
  aesd.8  q0, q12
  veor.8  q0, q0, q12
  aesimc.8 q0, q0
  veor.8  q0, q0, q11
  aesd.8  q0, q11
  veor.8  q0, q0, q11
  aesimc.8 q0, q0
  veor.8  q0, q0, q10
  aesd.8  q0, q10
  veor.8  q0, q0, q10
  aesimc.8 q0, q0
  veor.8  q0, q0, q9
  aesd.8  q0, q9
  veor.8  q0, q0, q9
  aesimc.8 q0, q0
  veor.8  q0, q0, q8
  aesd.8  q0, q8
  veor.8  q0, q0, q8
  aesimc.8 q0, q0
  veor.8  q0, q0, q7
  aesd.8  q0, q7
  veor.8  q0, q0, q7
  aesimc.8 q0, q0
  veor.8  q0, q0, q6
  aesd.8  q0, q6
  veor.8  q0, q0, q6
  aesimc.8 q0, q0
  veor.8  q0, q0, q5
  aesd.8  q0, q5
  veor.8  q0, q0, q5
  aesimc.8 q0, q0
  veor.8  q0, q0, q4
  aesd.8  q0, q4
  veor.8  q0, q0, q4
  aesimc.8 q0, q0
  veor.8  q0, q0, q3
  aesd.8  q0, q3
  veor.8  q0, q0, q3
  aesimc.8 q0, q0
  veor.8  q0, q0, q2
  aesd.8  q0, q2
  veor.8  q0, q0, q2
  aesimc.8 q0, q0
  veor.8  q0, q0, q1
  aesd.8  q0, q1
  veor.8  q0, q0, q1

  vst1.u8 {q0},[r1]

  restore_caller_registers
  bx lr
