#!/usr/bin/env python

# AES Shellcode Encrypter / Decrypter
# For SLAE32
# Howard McGreehan

# PyCrypto
from Crypto.Cipher import AES
import ctypes
#from ctypes import *
import mmap
import sys, os
import argparse
import base64


parser = argparse.ArgumentParser()
parser.add_argument("-s", "--shellcode", help="Shellcode in \\x90 format", type=str, required=True)
parser.add_argument("-k", "--key", help="The AES key", type=str, required=True)
parser.add_argument("-d", help="Base64'd, AES CBC encrypted shellcode", action="store_true")
parser.add_argument("-e", help="Encrypt shellcode with AES CBC", action="store_true")
args = parser.parse_args()

# First check the args
if len(sys.argv) < 3:
    print("[!] Not enough arguments, exiting.")
    sys.exit()

# Check the shellcode length and pad it if necessary
def padShellcode(shellcode):
    pl = 16 - (len(shellcode) % 16)

    if (pl >= 1 or pl != 16):
        print("[!] Shellcode is %s bytes, %s bytes of padding are needed for AES CBC encryption" % (len(shellcode), pl))
        paddedShellcode = bytearray(b'\x90' * pl + shellcode)
    else: 
        print("[+] Shellcode is a multiple of 16, no padding is required! Length: %s" % len(shellcode))
    return paddedShellcode

def encrypt(key, data):
    iv = os.urandom(16)
    aes = AES.new(key, AES.MODE_CBC, iv)
    return iv + aes.encrypt(bytes(data))

def decrypt(key, cipherText):
    iv = cipherText[:AES.block_size]
    aes = AES.new(key, AES.MODE_CBC, iv)
    decoded = aes.decrypt(cipherText)
    return decoded[AES.block_size:]

def normalize(s):
    normalized = ""
    for byte in bytearray(s):
         normalized += '\\x%02x' % (byte)
    return normalized

def py3ShellcodeFix(s):
    # get the string and split on the \x characters
    code = s.split('\\x')
    # remove any blank strings that may appear (you might also be able to get away with just doing code[1:] instead)
    code = list(filter(lambda x: x != '', code))
    # for each base 16 "character", convert it into a list of integers, then convert all that into a bytearray
    return bytearray([int(x, 16) for x in code])

# Will NOT work in python3 / newer machines
def runShellcode(shellcode):
    # Allocate memory with a RWX private anonymous mmap
    exec_mem = mmap.mmap(-1, len(shellcode),
                         prot = mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
                         flags = mmap.MAP_ANONYMOUS | mmap.MAP_PRIVATE)

    # Copy shellcode from bytes object to executable memory
    exec_mem.write(shellcode)

    # Cast the memory to a C function object
    ctypes_buffer = ctypes.c_int.from_buffer(exec_mem)
    function = ctypes.CFUNCTYPE( ctypes.c_int64 )(ctypes.addressof(ctypes_buffer))
    function._avoid_gc_for_mmap = exec_mem

    # Return pointer to shell code function in executable memory
    return function

if args.e:    
    
    shellcode = py3ShellcodeFix(args.shellcode)

    paddedShellcode = padShellcode(shellcode)
    #print(paddedShellcode)
    encryptedShellcode = encrypt(args.key, paddedShellcode)
    n = normalize(encryptedShellcode)
    print("[+] Encrypted shellcode (raw):\n%s\n" % encryptedShellcode)
    print("[+] Encrypted shellcode (\\x):\n%s\n" % n)
    print("[+] Encrypted shellcode (base64):\n%s\n" % base64.b64encode(encryptedShellcode))

if args.d:
    shellcode = py3ShellcodeFix(args.shellcode)
    decrypted = decrypt(args.key, bytes(shellcode))
    n = normalize(decrypted)
    print("[+] Decrypted shellcode (raw):\n%s\n" % decrypted)
    print("[+] Decrypted shellcode (\\x):\n%s" % n)
    
    print("[*] Executing shellcode...")

    runShellcode(decrypted)()



