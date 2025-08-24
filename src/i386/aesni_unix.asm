; Copyright (c) 2025 Jakub Juszczakiewicz
; All rights reserved.

BITS 32

SECTION .note.GNU-stack noalloc noexec nowrite progbits

SECTION .text
	GLOBAL kit_aes_encrypt_block_128_asm
	GLOBAL kit_aes_encrypt_block_192_asm
	GLOBAL kit_aes_encrypt_block_256_asm
	GLOBAL kit_aes_decrypt_block_128_asm
	GLOBAL kit_aes_decrypt_block_192_asm
	GLOBAL kit_aes_decrypt_block_256_asm
	GLOBAL kit_aes_cpu_is_supported
	GLOBAL kit_aes_test

kit_aes_cpu_is_supported:
	push ebx
	push ecx
	push edx

	mov eax, 1
	cpuid
	mov eax, ecx
	shr eax, 25
	and eax, 1

	pop edx
	pop ecx
	pop ebx
	ret

kit_aes_encrypt_block_128_asm:
	push	 ebp
	mov	ebp,	esp

	push	edx
	push	edi
	push	esi

	mov	edi,	[ebp + 8]
	mov	esi,	[ebp + 12]
	mov	edx,	[ebp + 16]

	movdqu	xmm0,	[edx]
	movdqu	xmm1,	[edi]
	movdqu	xmm2,	[edi + 16]
	movdqu	xmm3,	[edi + 32]
	movdqu	xmm4,	[edi + 48]
	movdqu	xmm5,	[edi + 64]
	movdqu	xmm6,	[edi + 80]
	movdqu	xmm7,	[edi + 96]

	xorpd	xmm0,	xmm1
	aesenc	xmm0,	xmm2
	aesenc	xmm0,	xmm3
	aesenc	xmm0,	xmm4
	aesenc	xmm0,	xmm5
	aesenc	xmm0,	xmm6
	aesenc	xmm0,	xmm7

	movdqu	xmm1,	[edi + 112]
	movdqu	xmm2,	[edi + 128]
	movdqu	xmm3,	[edi + 144]
	movdqu	xmm4,	[edi + 160]

	aesenc	xmm0,	xmm1
	aesenc	xmm0,	xmm2
	aesenc	xmm0,	xmm3
	aesenclast	xmm0,	xmm4

	movdqu	[esi],	xmm0

	pop esi
	pop edi
	pop edx
	mov esp, ebp
	pop ebp
	ret

kit_aes_encrypt_block_192_asm:
	push	 ebp
	mov	ebp,	esp

	push	edx
	push	edi
	push	esi

	mov	edi,	[ebp + 8]
	mov	esi,	[ebp + 12]
	mov	edx,	[ebp + 16]

	movdqu	xmm0,	[edx]
	movdqu	xmm1,	[edi]
	movdqu	xmm2,	[edi + 16]
	movdqu	xmm3,	[edi + 32]
	movdqu	xmm4,	[edi + 48]
	movdqu	xmm5,	[edi + 64]
	movdqu	xmm6,	[edi + 80]
	movdqu	xmm7,	[edi + 96]

	xorpd	xmm0,	xmm1
	aesenc	xmm0,	xmm2
	aesenc	xmm0,	xmm3
	aesenc	xmm0,	xmm4
	aesenc	xmm0,	xmm5
	aesenc	xmm0,	xmm6
	aesenc	xmm0,	xmm7

	movdqu	xmm1,	[edi + 112]
	movdqu	xmm2,	[edi + 128]
	movdqu	xmm3,	[edi + 144]
	movdqu	xmm4,	[edi + 160]
	movdqu	xmm5,	[edi + 176]
	movdqu	xmm6,	[edi + 192]

	aesenc	xmm0,	xmm1
	aesenc	xmm0,	xmm2
	aesenc	xmm0,	xmm3
	aesenc	xmm0,	xmm4
	aesenc	xmm0,	xmm5
	aesenclast	xmm0,	xmm6

	movdqu	[esi],	xmm0

	pop esi
	pop edi
	pop edx
	mov esp, ebp
	pop ebp
	ret

kit_aes_encrypt_block_256_asm:
	push	 ebp
	mov	ebp,	esp

	push	edx
	push	edi
	push	esi

	mov	edi,	[ebp + 8]
	mov	esi,	[ebp + 12]
	mov	edx,	[ebp + 16]

	movdqu	xmm0,	[edx]
	movdqu	xmm1,	[edi]
	movdqu	xmm2,	[edi + 16]
	movdqu	xmm3,	[edi + 32]
	movdqu	xmm4,	[edi + 48]
	movdqu	xmm5,	[edi + 64]
	movdqu	xmm6,	[edi + 80]
	movdqu	xmm7,	[edi + 96]

	xorpd	xmm0,	xmm1
	aesenc	xmm0,	xmm2
	aesenc	xmm0,	xmm3
	aesenc	xmm0,	xmm4
	aesenc	xmm0,	xmm5
	aesenc	xmm0,	xmm6
	aesenc	xmm0,	xmm7
	
	movdqu	xmm1,	[edi + 112]
	movdqu	xmm2,	[edi + 128]
	movdqu	xmm3,	[edi + 144]
	movdqu	xmm4,	[edi + 160]
	movdqu	xmm5,	[edi + 176]
	movdqu	xmm6,	[edi + 192]
	movdqu	xmm7,	[edi + 208]

	aesenc	xmm0,	xmm1
	aesenc	xmm0,	xmm2
	aesenc	xmm0,	xmm3
	aesenc	xmm0,	xmm4
	aesenc	xmm0,	xmm5
	aesenc	xmm0,	xmm6
	aesenc	xmm0,	xmm7

	movdqu	xmm1,	[edi + 224]
	aesenclast	xmm0,	xmm1

	movdqu	[esi],	xmm0

	pop esi
	pop edi
	pop edx
	mov esp, ebp
	pop ebp
	ret

kit_aes_decrypt_block_128_asm:
	push	 ebp
	mov	ebp,	esp

	push	edx
	push	edi
	push	esi

	mov	edi,	[ebp + 8]
	mov	esi,	[ebp + 12]
	mov	edx,	[ebp + 16]

	movdqu	xmm0,	[edx]
	movdqu	xmm1,	[edi + 160]
	movdqu	xmm2,	[edi + 144]
	movdqu	xmm3,	[edi + 128]
	movdqu	xmm4,	[edi + 112]
	movdqu	xmm5,	[edi + 96]
	movdqu	xmm6,	[edi + 80]
	movdqu	xmm7,	[edi + 64]

	xorpd	xmm0,	xmm1
	aesimc	xmm1,	xmm2
	aesdec	xmm0,	xmm1
	aesimc	xmm1,	xmm3
	aesdec	xmm0,	xmm1
	aesimc	xmm1,	xmm4
	aesdec	xmm0,	xmm1
	aesimc	xmm1,	xmm5
	aesdec	xmm0,	xmm1
	aesimc	xmm1,	xmm6
	aesdec	xmm0,	xmm1
	aesimc	xmm1,	xmm7
	aesdec	xmm0,	xmm1

	movdqu	xmm2,	[edi + 48]
	movdqu	xmm3,	[edi + 32]
	movdqu	xmm4,	[edi + 16]
	movdqu	xmm5,	[edi]

	aesimc	xmm1,	xmm2
	aesdec	xmm0,	xmm1
	aesimc	xmm1,	xmm3
	aesdec	xmm0,	xmm1
	aesimc	xmm1,	xmm4
	aesdec	xmm0,	xmm1
	aesdeclast	xmm0,	xmm5

	movdqu	[esi],	xmm0

	pop esi
	pop edi
	pop edx
	mov esp, ebp
	pop ebp
	ret

kit_aes_decrypt_block_192_asm:
	push	 ebp
	mov	ebp,	esp

	push	edx
	push	edi
	push	esi

	mov	edi,	[ebp + 8]
	mov	esi,	[ebp + 12]
	mov	edx,	[ebp + 16]

	movdqu	xmm0,	[edx]
	movdqu	xmm1,	[edi + 192]
	movdqu	xmm2,	[edi + 176]
	movdqu	xmm3,	[edi + 160]
	movdqu	xmm4,	[edi + 144]
	movdqu	xmm5,	[edi + 128]
	movdqu	xmm6,	[edi + 112]
	movdqu	xmm7,	[edi + 96]

	xorpd	xmm0,	xmm1
	aesimc	xmm1,	xmm2
	aesdec	xmm0,	xmm1
	aesimc	xmm1,	xmm3
	aesdec	xmm0,	xmm1
	aesimc	xmm1,	xmm4
	aesdec	xmm0,	xmm1
	aesimc	xmm1,	xmm5
	aesdec	xmm0,	xmm1
	aesimc	xmm1,	xmm6
	aesdec	xmm0,	xmm1
	aesimc	xmm1,	xmm7
	aesdec	xmm0,	xmm1

	movdqu	xmm2,	[edi + 80]
	movdqu	xmm3,	[edi + 64]
	movdqu	xmm4,	[edi + 48]
	movdqu	xmm5,	[edi + 32]
	movdqu	xmm6,	[edi + 16]
	movdqu	xmm7,	[edi]

	aesimc	xmm1,	xmm2
	aesdec	xmm0,	xmm1
	aesimc	xmm1,	xmm3
	aesdec	xmm0,	xmm1
	aesimc	xmm1,	xmm4
	aesdec	xmm0,	xmm1
	aesimc	xmm1,	xmm5
	aesdec	xmm0,	xmm1
	aesimc	xmm1,	xmm6
	aesdec	xmm0,	xmm1
	aesdeclast	xmm0,	xmm7

	movdqu	[esi],	xmm0

	pop esi
	pop edi
	pop edx
	mov esp, ebp
	pop ebp
	ret

kit_aes_decrypt_block_256_asm:
	push	 ebp
	mov	ebp,	esp

	push	edx
	push	edi
	push	esi

	mov	edi,	[ebp + 8]
	mov	esi,	[ebp + 12]
	mov	edx,	[ebp + 16]

	movdqu	xmm0,	[edx]
	movdqu	xmm1,	[edi + 224]
	movdqu	xmm2,	[edi + 208]
	movdqu	xmm3,	[edi + 192]
	movdqu	xmm4,	[edi + 176]
	movdqu	xmm5,	[edi + 160]
	movdqu	xmm6,	[edi + 144]
	movdqu	xmm7,	[edi + 128]

	xorpd	xmm0,	xmm1
	aesimc	xmm1,	xmm2
	aesdec	xmm0,	xmm1
	aesimc	xmm1,	xmm3
	aesdec	xmm0,	xmm1
	aesimc	xmm1,	xmm4
	aesdec	xmm0,	xmm1
	aesimc	xmm1,	xmm5
	aesdec	xmm0,	xmm1
	aesimc	xmm1,	xmm6
	aesdec	xmm0,	xmm1
	aesimc	xmm1,	xmm7
	aesdec	xmm0,	xmm1

	movdqu	xmm2,	[edi + 112]
	movdqu	xmm3,	[edi + 96]
	movdqu	xmm4,	[edi + 80]
	movdqu	xmm5,	[edi + 64]
	movdqu	xmm6,	[edi + 48]
	movdqu	xmm7,	[edi + 32]

	aesimc	xmm1,	xmm2
	aesdec	xmm0,	xmm1
	aesimc	xmm1,	xmm3
	aesdec	xmm0,	xmm1
	aesimc	xmm1,	xmm4
	aesdec	xmm0,	xmm1
	aesimc	xmm1,	xmm5
	aesdec	xmm0,	xmm1
	aesimc	xmm1,	xmm6
	aesdec	xmm0,	xmm1
	aesimc	xmm1,	xmm7
	aesdec	xmm0,	xmm1

	movdqu	xmm2,	[edi + 16]
	movdqu	xmm3,	[edi]

	aesimc	xmm1,	xmm2
	aesdec	xmm0,	xmm1
	aesdeclast	xmm0,	xmm3

	movdqu	[esi],	xmm0

	pop esi
	pop edi
	pop edx
	mov esp, ebp
	pop ebp
	ret
