#!/usr/bin/env python3

import sys
import binascii
import base64

# ROT X + NOT encoder / decoder

if len(sys.argv) < 4:
    print("Usage: rot-not.py /file/to/encode.bin 4 /path/to/outfile.bin")
    sys.exit()
else:
    f = sys.argv[1]
    try:
        with open(f, 'rb') as fin:
            sc = fin.read()
    except Exception as e:
        print("[!] Error: \n")
        print(e)
        sys.exit()

# Set up a few variables for use in our loop
encoded = bytearray()
decoded = bytearray()
shift = int(sys.argv[2])
outfile = sys.argv[3]

# Create a loop to encode our sc
for byte in bytearray(sc):
    tmp1 = (byte + shift) % 256
    tmp2 = ~tmp1 & 0xff
    encoded.append(tmp2)

# Simple decoder
# Does the inverse of above
for byte in bytearray(encoded):
    tmp1 = ~byte & 0xff
    tmp2 = (tmp1 - shift) % 256
    decoded.append(tmp2)

with open(outfile, 'wb') as fout:
    fout.write(encoded)

print("Shellcode length (in): %s" % len(sc))
print("Shellcode length (out): %s" % len(encoded))
print("Encoded bytes written to '%s'" % outfile)
