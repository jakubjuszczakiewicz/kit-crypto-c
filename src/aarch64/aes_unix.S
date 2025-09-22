# Copyright (c) 2025 Jakub Juszczakiewicz
# All rights reserved.

.text

.global kit_aes_encrypt_block_128_asm
.global kit_aes_encrypt_block_192_asm
.global kit_aes_encrypt_block_256_asm
.global kit_aes_decrypt_block_128_asm
.global kit_aes_decrypt_block_192_asm
.global kit_aes_decrypt_block_256_asm

.p2align 4

.macro preserve_caller_registers
  stp d8,d9,[sp,#-16]!
  stp d10,d11,[sp,#-16]!
  stp d12,d13,[sp,#-16]!
  stp d14,d15,[sp,#-16]!
.endm

.macro restore_caller_registers
  ldp d14,d15,[sp],#16
  ldp d12,d13,[sp],#16
  ldp d10,d11,[sp],#16
  ldp d8,d9,[sp],#16
.endm

.p2align 4
kit_aes_encrypt_block_128_asm:
  preserve_caller_registers

  ld1 {v0.16b},[x2],#16
  ld1 {v1.16b, v2.16b, v3.16b, v4.16b},[x0],#64
  ld1 {v5.16b, v6.16b, v7.16b, v8.16b},[x0],#64
  ld1 {v9.16b, v10.16b, v11.16b},[x0],#48

  aese    v0.16b, v1.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v2.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v3.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v4.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v5.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v6.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v7.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v8.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v9.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v10.16b
  eor     v0.16b, v0.16b, v11.16b

  st1 {v0.16b},[x1],#16

  restore_caller_registers
  ret

.p2align 4
kit_aes_encrypt_block_192_asm:
  preserve_caller_registers

  ld1 {v0.16b},[x2],#16
  ld1 {v1.16b, v2.16b, v3.16b, v4.16b},[x0],#64
  ld1 {v5.16b, v6.16b, v7.16b, v8.16b},[x0],#64
  ld1 {v9.16b, v10.16b, v11.16b, v12.16b},[x0],#64
  ld1 {v13.16b},[x0],#16

  aese    v0.16b, v1.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v2.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v3.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v4.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v5.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v6.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v7.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v8.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v9.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v10.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v11.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v12.16b
  eor     v0.16b, v0.16b, v13.16b

  st1 {v0.16b},[x1],#16

  restore_caller_registers
  ret

.p2align 4
kit_aes_encrypt_block_256_asm:
  preserve_caller_registers

  ld1 {v0.16b},[x2],#16
  ld1 {v1.16b, v2.16b, v3.16b, v4.16b},[x0],#64
  ld1 {v5.16b, v6.16b, v7.16b, v8.16b},[x0],#64
  ld1 {v9.16b, v10.16b, v11.16b, v12.16b},[x0],#64
  ld1 {v13.16b, v14.16b, v15.16b},[x0],#48

  aese    v0.16b, v1.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v2.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v3.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v4.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v5.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v6.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v7.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v8.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v9.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v10.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v11.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v12.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v13.16b
  aesmc   v0.16b, v0.16b
  aese    v0.16b, v14.16b
  eor     v0.16b, v0.16b, v15.16b

  st1 {v0.16b},[x1],#16

  restore_caller_registers
  ret

.p2align 4
kit_aes_decrypt_block_128_asm:
  preserve_caller_registers

  ld1 {v0.16b},[x2],#16
  ld1 {v1.16b, v2.16b, v3.16b, v4.16b},[x0],#64
  ld1 {v5.16b, v6.16b, v7.16b, v8.16b},[x0],#64
  ld1 {v9.16b, v10.16b, v11.16b},[x0],#48

  aesd    v0.16b, v11.16b
  eor     V0.16b, V0.16b, v10.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v9.16b
  aesd    v0.16b, v9.16b
  eor     V0.16b, V0.16b, v9.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v8.16b
  aesd    v0.16b, v8.16b
  eor     V0.16b, V0.16b, v8.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v7.16b
  aesd    v0.16b, v7.16b
  eor     V0.16b, V0.16b, v7.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v6.16b
  aesd    v0.16b, v6.16b
  eor     V0.16b, V0.16b, v6.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v5.16b
  aesd    v0.16b, v5.16b
  eor     V0.16b, V0.16b, v5.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v4.16b
  aesd    v0.16b, v4.16b
  eor     V0.16b, V0.16b, v4.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v3.16b
  aesd    v0.16b, v3.16b
  eor     V0.16b, V0.16b, v3.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v2.16b
  aesd    v0.16b, v2.16b
  eor     V0.16b, V0.16b, v2.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v1.16b
  aesd    v0.16b, v1.16b
  eor     V0.16b, V0.16b, v1.16b

  st1 {v0.16b},[x1],#16

  restore_caller_registers
  ret

.p2align 4
kit_aes_decrypt_block_192_asm:
  preserve_caller_registers

  ld1 {v0.16b},[x2],#16
  ld1 {v1.16b, v2.16b, v3.16b, v4.16b},[x0],#64
  ld1 {v5.16b, v6.16b, v7.16b, v8.16b},[x0],#64
  ld1 {v9.16b, v10.16b, v11.16b, v12.16b},[x0],#64
  ld1 {v13.16b},[x0],#16

  aesd    v0.16b, v13.16b
  eor     V0.16b, V0.16b, v12.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v11.16b
  aesd    v0.16b, v11.16b
  eor     V0.16b, V0.16b, v11.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v10.16b
  aesd    v0.16b, v10.16b
  eor     V0.16b, V0.16b, v10.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v9.16b
  aesd    v0.16b, v9.16b
  eor     V0.16b, V0.16b, v9.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v8.16b
  aesd    v0.16b, v8.16b
  eor     V0.16b, V0.16b, v8.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v7.16b
  aesd    v0.16b, v7.16b
  eor     V0.16b, V0.16b, v7.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v6.16b
  aesd    v0.16b, v6.16b
  eor     V0.16b, V0.16b, v6.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v5.16b
  aesd    v0.16b, v5.16b
  eor     V0.16b, V0.16b, v5.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v4.16b
  aesd    v0.16b, v4.16b
  eor     V0.16b, V0.16b, v4.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v3.16b
  aesd    v0.16b, v3.16b
  eor     V0.16b, V0.16b, v3.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v2.16b
  aesd    v0.16b, v2.16b
  eor     V0.16b, V0.16b, v2.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v1.16b
  aesd    v0.16b, v1.16b
  eor     V0.16b, V0.16b, v1.16b

  st1 {v0.16b},[x1],#16

  restore_caller_registers
  ret

.p2align 4
kit_aes_decrypt_block_256_asm:
  preserve_caller_registers

  ld1 {v0.16b},[x2],#16
  ld1 {v1.16b, v2.16b, v3.16b, v4.16b},[x0],#64
  ld1 {v5.16b, v6.16b, v7.16b, v8.16b},[x0],#64
  ld1 {v9.16b, v10.16b, v11.16b, v12.16b},[x0],#64
  ld1 {v13.16b, v14.16b, v15.16b},[x0],#48

  aesd    v0.16b, v15.16b
  eor     V0.16b, V0.16b, v14.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v13.16b
  aesd    v0.16b, v13.16b
  eor     V0.16b, V0.16b, v13.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v12.16b
  aesd    v0.16b, v12.16b
  eor     V0.16b, V0.16b, v12.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v11.16b
  aesd    v0.16b, v11.16b
  eor     V0.16b, V0.16b, v11.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v10.16b
  aesd    v0.16b, v10.16b
  eor     V0.16b, V0.16b, v10.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v9.16b
  aesd    v0.16b, v9.16b
  eor     V0.16b, V0.16b, v9.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v8.16b
  aesd    v0.16b, v8.16b
  eor     V0.16b, V0.16b, v8.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v7.16b
  aesd    v0.16b, v7.16b
  eor     V0.16b, V0.16b, v7.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v6.16b
  aesd    v0.16b, v6.16b
  eor     V0.16b, V0.16b, v6.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v5.16b
  aesd    v0.16b, v5.16b
  eor     V0.16b, V0.16b, v5.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v4.16b
  aesd    v0.16b, v4.16b
  eor     V0.16b, V0.16b, v4.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v3.16b
  aesd    v0.16b, v3.16b
  eor     V0.16b, V0.16b, v3.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v2.16b
  aesd    v0.16b, v2.16b
  eor     V0.16b, V0.16b, v2.16b
  aesimc  v0.16b, v0.16b
  eor     V0.16b, V0.16b, v1.16b
  aesd    v0.16b, v1.16b
  eor     V0.16b, V0.16b, v1.16b

  st1 {v0.16b},[x1],#16

  restore_caller_registers
  ret
