#!/usr/bin/env python3

import base64
from des import * #python3 -m pip install des
import sys

try:
        path = sys.argv[1]
except:
        exit("Supply base64-encoded encrypted password as argv1")

def decrypt(hash):
        hash = base64.b64decode(hash.encode('utf-8'))
        key = DesKey(b"7ly6UznJ")
        return key.decrypt(hash,initial=b"XuVUm5fR",padding=True).decode('utf-8')

print(f'Decrypted Password: {decrypt(sys.argv[1])}')
