#!/usr/bin/python3

import hashlib
import binascii
import sys

if len(sys.argv) < 2:
    print("Usage: script.py <string_to_hash>")
    sys.exit(1)

input_string = sys.argv[1]

hash = hashlib.new('md4', input_string.encode('utf-16le')).digest()
print(binascii.hexlify(hash).decode())
