#!/usr/bin/python3

from pwn import * 

payload  = p32(0x1, endian='big')
payload += p32(0x2, endian='big')
# payload += p32(0x4, endian='big')
payload += b"AAAABBBBCCCCDDDD"
open('/home/user/symqemu-go/tests/symqemu/binaries/fdp/out/input.txt', 'wb').write(payload)