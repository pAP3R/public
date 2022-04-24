#!/usr/bin/env python3

import binascii
import sys

if len(sys.argv) < 2:
    print("[!] Usage: file2hex.py FILENAME\n")
    sys.exit()

f = sys.argv[1]

with open(f, 'rb') as fin:
    c = fin.read()

print("[+] Hex content:\n" + str(binascii.hexlify(c)))
