#!/usr/bin/env python3
"""
Recover 33-char input for the MD5-triplet check program.

Usage:
    python3 recover_input.py

Notes:
 - PyPy is recommended for speed, but CPython + multiple CPUs works fine.
 - This will brute-force 3-byte MD5 preimages (≈16.7M hashes per digest).
 - The script parallelizes across the first byte (256 tasks per digest).
"""

from hashlib import md5
from multiprocessing import Pool, cpu_count
from functools import partial
import sys

# ---- paste the 11 expected digests (32 hex chars each, lowercase) ----
DIGESTS = [
    "0ad4e843e75e1c324acbaa59cd5e9b28",
    "cb630f1d7e6fcf44655f79c50b1f4bed",
    "6b3e7418cfde37115f10ac292953ace3",
    "498806dbac9ee2a96bdbd6c250e3b169",
    "3edc0700a392dbda8453ee353c8d8014",
    "77d3c6f64bcdf3c4fd7774f1b4897a22",
    "e5b43297081b035ab10ea3b0b17a952e",
    "bf408250ca67eeea912df1bdccb39b08",
    "6d8d1c700b299a88d9d1ded87968e7d1",
    "1e29590853e44df40c8c12abeddedc36",
    "5c4128660e545fcb09201f2cf3ab3b4b",
]

# 33 per your decompilation, in this exact order:
CONSTS = [
    0x2e,0x2d,0xa2,0xc3,0x5b,0x1c,0x1e,0x5d,0x5e,0x42,0x4c,
    0x29,0x17,0x50,0x16,0x40,0x15,0x4d,0x17,0x21,0x26,0x37,
    0x84,0x07,0x21,0x0d,0x2b,0x50,0x3a,0x12,0x15,0x5b,0x22
]

def _worker_check_a(a, target_bytes):
    """Check all (b, c) for given a. Return bytes((a,b,c)) on match else None."""
    # local variables for speed
    for b in range(256):
        for c in range(256):
            s = bytes((a, b, c))
            if md5(s).hexdigest().encode() == target_bytes:
                return s
    return None

def brute_one_parallel(target_hex: str, procs=None):
    """Find a 3-byte preimage for target_hex using multiprocessing over first byte."""
    target_bytes = target_hex.lower().encode()
    procs = procs or cpu_count()
    # Use Pool to map the 256 first-byte values
    with Pool(processes=min(procs, 256)) as pool:
        worker = partial(_worker_check_a, target_bytes=target_bytes)
        # imap_unordered yields results as they finish
        for res in pool.imap_unordered(worker, range(256)):
            if res is not None:
                pool.terminate()  # stop other workers quickly
                return res
    raise ValueError(f"No 3-byte preimage found for {target_hex!r}")

def main():
    if len(DIGESTS) != 11:
        print("[!] Please paste the 11 MD5 digests into DIGESTS[] (found", len(DIGESTS),")")
        sys.exit(1)

    triplets = []
    print(f"[*] Using up to {cpu_count()} worker processes")
    for i, d in enumerate(DIGESTS):
        if len(d) != 32 or any(ch not in "0123456789abcdef" for ch in d.lower()):
            print(f"[!] Digest #{i+1} looks invalid: {d!r}")
            sys.exit(1)

    for i, d in enumerate(DIGESTS):
        print(f"[*] Brute-forcing triplet {i+1}/11 for digest {d} ...")
        s = brute_one_parallel(d)
        assert len(s) == 3
        print(f"    [+] Found triplet: {s.hex()}  (bytes: {list(s)})")
        triplets.append(s)

    Y = b"".join(triplets)  # length 33
    if len(Y) != 33:
        print("[!] Internal error: expected 33 bytes of Y, got", len(Y))
        sys.exit(1)

    # Invert transform: Y[i] = (X[i] + 2) XOR CONSTS[i]  ->  X[i] = ((Y[i] XOR CONSTS[i]) - 2) & 0xFF
    X = bytes( ((Y[i] ^ CONSTS[i]) - 2) & 0xFF for i in range(33) )

    try:
        s = X.decode("utf-8")
    except UnicodeDecodeError:
        # show printable ascii or \x escapes
        s = ''.join(chr(b) if 32 <= b < 127 else f'\\x{b:02x}' for b in X)

    print("\n=== Paste this EXACTLY after the prompt ===")
    print(s)
    print("=== (length should be 33) ===")

if __name__ == "__main__":
    main()
