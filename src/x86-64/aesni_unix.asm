; Copyright (c) 2025 Jakub Juszczakiewicz
; All rights reserved.

BITS 64

SECTION .note.GNU-stack noalloc noexec nowrite progbits

SECTION .text
	GLOBAL kit_aes_encrypt_block_128_asm
	GLOBAL kit_aes_encrypt_block_192_asm
	GLOBAL kit_aes_encrypt_block_256_asm
	GLOBAL kit_aes_decrypt_block_128_asm
	GLOBAL kit_aes_decrypt_block_192_asm
	GLOBAL kit_aes_decrypt_block_256_asm
	GLOBAL kit_aes_cpu_is_supported

kit_aes_cpu_is_supported:
	push rbx

	mov rax, 1
	cpuid
	mov eax, ecx
	shr eax, 25
	and eax, 1

	pop rbx
	ret

kit_aes_encrypt_block_128_asm:
	movdqu	xmm0,	[rdx]
	movdqu	xmm1,	[rdi]
	movdqu	xmm2,	[rdi + 16]
	movdqu	xmm3,	[rdi + 32]
	movdqu	xmm4,	[rdi + 48]
	movdqu	xmm5,	[rdi + 64]
	movdqu	xmm6,	[rdi + 80]
	movdqu	xmm7,	[rdi + 96]
	movdqu	xmm8,	[rdi + 112]
	movdqu	xmm9,	[rdi + 128]
	movdqu	xmm10,	[rdi + 144]
 	movdqu	xmm11,	[rdi + 160]

	xorpd	xmm0,	xmm1
	aesenc	xmm0,	xmm2
	aesenc	xmm0,	xmm3
	aesenc	xmm0,	xmm4
	aesenc	xmm0,	xmm5
	aesenc	xmm0,	xmm6
	aesenc	xmm0,	xmm7
	aesenc	xmm0,	xmm8
	aesenc	xmm0,	xmm9
	aesenc	xmm0,	xmm10
	aesenclast	xmm0,	xmm11

	movdqu	[rsi],	xmm0
	ret

kit_aes_encrypt_block_192_asm:
	movdqu	xmm1,	[rdi]
	movdqu	xmm0,	[rdx]
	movdqu	xmm2,	[rdi + 16]
	movdqu	xmm3,	[rdi + 32]
	movdqu	xmm4,	[rdi + 48]
	movdqu	xmm5,	[rdi + 64]
	movdqu	xmm6,	[rdi + 80]
	movdqu	xmm7,	[rdi + 96]
	movdqu	xmm8,	[rdi + 112]
	movdqu	xmm9,	[rdi + 128]
	movdqu	xmm10,	[rdi + 144]
	movdqu	xmm11,	[rdi + 160]
	movdqu	xmm12,	[rdi + 176]
	movdqu	xmm13,	[rdi + 192]

	xorpd	xmm0,	xmm1
	aesenc	xmm0,	xmm2
	aesenc	xmm0,	xmm3
	aesenc	xmm0,	xmm4
	aesenc	xmm0,	xmm5
	aesenc	xmm0,	xmm6
	aesenc	xmm0,	xmm7
	aesenc	xmm0,	xmm8
	aesenc	xmm0,	xmm9
	aesenc	xmm0,	xmm10
	aesenc	xmm0,	xmm11
	aesenc	xmm0,	xmm12
	aesenclast	xmm0,	xmm13

	movdqu	[rsi],	xmm0
	ret

kit_aes_encrypt_block_256_asm:
	movdqu	xmm1,	[rdi]
	movdqu	xmm0,	[rdx]
	movdqu	xmm2,	[rdi + 16]
	movdqu	xmm3,	[rdi + 32]
	movdqu	xmm4,	[rdi + 48]
	movdqu	xmm5,	[rdi + 64]
	movdqu	xmm6,	[rdi + 80]
	movdqu	xmm7,	[rdi + 96]
	movdqu	xmm8,	[rdi + 112]
	movdqu	xmm9,	[rdi + 128]
	movdqu	xmm10,	[rdi + 144]
	movdqu	xmm11,	[rdi + 160]
	movdqu	xmm12,	[rdi + 176]
	movdqu	xmm13,	[rdi + 192]
	movdqu	xmm14,	[rdi + 208]
	movdqu	xmm15,	[rdi + 224]

	xorpd	xmm0,	xmm1
	aesenc	xmm0,	xmm2
	aesenc	xmm0,	xmm3
	aesenc	xmm0,	xmm4
	aesenc	xmm0,	xmm5
	aesenc	xmm0,	xmm6
	aesenc	xmm0,	xmm7
	aesenc	xmm0,	xmm8
	aesenc	xmm0,	xmm9
	aesenc	xmm0,	xmm10
	aesenc	xmm0,	xmm11
	aesenc	xmm0,	xmm12
	aesenc	xmm0,	xmm13
	aesenc	xmm0,	xmm14
	aesenclast	xmm0,	xmm15

	movdqu	[rsi],	xmm0
	ret

kit_aes_decrypt_block_128_asm:
	movdqu	xmm0,	[rdx]
	movdqu	xmm1,	[rdi]
	movdqu	xmm2,	[rdi + 16]
	movdqu	xmm3,	[rdi + 32]
	movdqu	xmm4,	[rdi + 48]
	movdqu	xmm5,	[rdi + 64]
	movdqu	xmm6,	[rdi + 80]
	movdqu	xmm7,	[rdi + 96]
	movdqu	xmm8,	[rdi + 112]
	movdqu	xmm9,	[rdi + 128]
	movdqu	xmm10,	[rdi + 144]
	movdqu	xmm11,	[rdi + 160]

	xorpd	xmm0,	xmm11
	aesimc	xmm11,	xmm10
	aesdec	xmm0,	xmm11
	aesimc	xmm11,	xmm9
	aesdec	xmm0,	xmm11
	aesimc	xmm11,	xmm8
	aesdec	xmm0,	xmm11
	aesimc	xmm11,	xmm7
	aesdec	xmm0,	xmm11
	aesimc	xmm11,	xmm6
	aesdec	xmm0,	xmm11
	aesimc	xmm11,	xmm5
	aesdec	xmm0,	xmm11
	aesimc	xmm11,	xmm4
	aesdec	xmm0,	xmm11
	aesimc	xmm11,	xmm3
	aesdec	xmm0,	xmm11
	aesimc	xmm11,	xmm2
	aesdec	xmm0,	xmm11
	aesdeclast	xmm0,	xmm1

	movdqu	[rsi],	xmm0
	ret

kit_aes_decrypt_block_192_asm:
	movdqu	xmm0,	[rdx]
	movdqu	xmm1,	[rdi]
	movdqu	xmm2,	[rdi + 16]
	movdqu	xmm3,	[rdi + 32]
	movdqu	xmm4,	[rdi + 48]
	movdqu	xmm5,	[rdi + 64]
	movdqu	xmm6,	[rdi + 80]
	movdqu	xmm7,	[rdi + 96]
	movdqu	xmm8,	[rdi + 112]
	movdqu	xmm9,	[rdi + 128]
	movdqu	xmm10,	[rdi + 144]
	movdqu	xmm11,	[rdi + 160]
	movdqu	xmm12,	[rdi + 176]
	movdqu	xmm13,	[rdi + 192]

	xorpd	xmm0,	xmm13
	aesimc	xmm13,	xmm12
	aesdec	xmm0,	xmm13
	aesimc	xmm13,	xmm11
	aesdec	xmm0,	xmm13
	aesimc	xmm13,	xmm10
	aesdec	xmm0,	xmm13
	aesimc	xmm13,	xmm9
	aesdec	xmm0,	xmm13
	aesimc	xmm13,	xmm8
	aesdec	xmm0,	xmm13
	aesimc	xmm13,	xmm7
	aesdec	xmm0,	xmm13
	aesimc	xmm13,	xmm6
	aesdec	xmm0,	xmm13
	aesimc	xmm13,	xmm5
	aesdec	xmm0,	xmm13
	aesimc	xmm13,	xmm4
	aesdec	xmm0,	xmm13
	aesimc	xmm13,	xmm3
	aesdec	xmm0,	xmm13
	aesimc	xmm13,	xmm2
	aesdec	xmm0,	xmm13
	aesdeclast	xmm0,	xmm1

	movdqu	[rsi],	xmm0
	ret

kit_aes_decrypt_block_256_asm:
	movdqu	xmm0,	[rdx]
	movdqu	xmm1,	[rdi]
	movdqu	xmm2,	[rdi + 16]
	movdqu	xmm3,	[rdi + 32]
	movdqu	xmm4,	[rdi + 48]
	movdqu	xmm5,	[rdi + 64]
	movdqu	xmm6,	[rdi + 80]
	movdqu	xmm7,	[rdi + 96]
	movdqu	xmm8,	[rdi + 112]
	movdqu	xmm9,	[rdi + 128]
	movdqu	xmm10,	[rdi + 144]
	movdqu	xmm11,	[rdi + 160]
	movdqu	xmm12,	[rdi + 176]
	movdqu	xmm13,	[rdi + 192]
	movdqu	xmm14,	[rdi + 208]
	movdqu	xmm15,	[rdi + 224]

	xorpd	xmm0,	xmm15
	aesimc	xmm15,	xmm14
	aesdec	xmm0,	xmm15
	aesimc	xmm15,	xmm13
	aesdec	xmm0,	xmm15
	aesimc	xmm15,	xmm12
	aesdec	xmm0,	xmm15
	aesimc	xmm15,	xmm11
	aesdec	xmm0,	xmm15
	aesimc	xmm15,	xmm10
	aesdec	xmm0,	xmm15
	aesimc	xmm15,	xmm9
	aesdec	xmm0,	xmm15
	aesimc	xmm15,	xmm8
	aesdec	xmm0,	xmm15
	aesimc	xmm15,	xmm7
	aesdec	xmm0,	xmm15
	aesimc	xmm15,	xmm6
	aesdec	xmm0,	xmm15
	aesimc	xmm15,	xmm5
	aesdec	xmm0,	xmm15
	aesimc	xmm15,	xmm4
	aesdec	xmm0,	xmm15
	aesimc	xmm15,	xmm3
	aesdec	xmm0,	xmm15
	aesimc	xmm15,	xmm2
	aesdec	xmm0,	xmm15
	aesdeclast	xmm0,	xmm1

	movdqu	[rsi],	xmm0
	ret
