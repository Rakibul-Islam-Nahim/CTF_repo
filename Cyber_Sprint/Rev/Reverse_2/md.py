#!/usr/bin/env python3
import re
import sys

if len(sys.argv) != 2:
    print("Usage: python3 extract_digests.py <binary>")
    sys.exit(1)

fn = sys.argv[1]
data = open(fn, "rb").read()

# Find ASCII 32-lowercase-hex followed by NUL (common storage for C strings)
pattern = re.compile(b'([0-9a-f]{32})\\x00')
matches = pattern.findall(data)

print("Found", len(matches), "32-hex strings (null-terminated).")
for i, m in enumerate(matches, 1):
    print(f"{i:2d}: {m.decode()}")
