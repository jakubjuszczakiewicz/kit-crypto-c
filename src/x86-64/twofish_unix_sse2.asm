BITS 64

SECTION .note.GNU-stack noalloc noexec nowrite progbits

SECTION .text
	GLOBAL kit_twofish_encrypt_n_blocks_128_asm

; void(const kit_twofish_key * key, uint8_t * output[], const uint8_t * input[], size_t n)
; rdi -> key[], rsi -> outs[], rdx -> ins[], rcx -> count
kit_twofish_encrypt_n_blocks_128_asm:
	push	rbx
	cmp	rcx,	4
;	jb
	lea	rbx,	[rdi]
	lea	r8,	[rdi + 8]
	lea	r9,	[rdi + 16]
	lea	r10,	[rdi + 24]
	movdqu	xmm0,	[rbx + 48]
	movdqu	xmm1,	[r8 + 48]
	movdqu	xmm2,	[r9 + 48]
	movdqu	xmm3,	[r10 + 48]
	lea	rbx,	[rdx]
	lea	r8,	[rdx + 8]
	lea	r9,	[rdx + 16]
	lea	r10,	[rdx + 24]
	movdqu	xmm4,	[rbx]
	movdqu	xmm5,	[r8]
	movdqu	xmm6,	[r9]
	movdqu	xmm7,	[r10]
	pxor xmm4, xmm0
	pxor xmm5, xmm1
	pxor xmm6, xmm2
	pxor xmm7, xmm3
	movdqa	xmm0,	xmm4
	movdqa	xmm1,	xmm5
	movdqa	xmm2,	xmm6
	movdqa	xmm3,	xmm7
	punpckldq	xmm0, 	xmm5
	punpckldq	xmm2, 	xmm7
	punpckhdq	xmm4, 	xmm5
	punpckhdq	xmm6, 	xmm7
	movdqa	xmm1,	xmm0
	movdqa	xmm3,	xmm2
	movdqa	xmm5,	xmm4
	movdqa	xmm7,	xmm6
	punpckldq	xmm0,	xmm3
	punpckhdq	xmm1,	xmm3
	punpckldq	xmm5,	xmm7
	punpckhdq	xmm6,	xmm7






	pop rbx
	ret
