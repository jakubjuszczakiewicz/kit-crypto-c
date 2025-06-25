; Copyright (c) 2025 Krypto-IT Jakub Juszczakiewicz
; All rights reserved.

BITS 64

SECTION .note.GNU-stack noalloc noexec nowrite progbits

SECTION .text
GLOBAL is_sse41_supported

is_sse41_supported:
	push rbx

	mov rax, 1
	cpuid
	shr ecx, 19
	and ecx, 1
	mov eax, ecx

	pop rbx
	ret
