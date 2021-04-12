# -*- coding: utf-8 -*-
from base64 import b64decode
from struct import pack
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Padding
from pbkdf2 import PBKDF2

import binascii
import hashlib
import sys

BLOCK_SIZE = 16

def _pad(data):
    in_len = len(data)
    pad_size = BLOCK_SIZE - (in_len % BLOCK_SIZE)
    return data.ljust(in_len + pad_size, pad_size.to_bytes(1, "little"))

def decode_data(data, key, mode):
    aes_iv = data[32:48]
    cipher = AES.new(key, mode, IV=aes_iv)
    result = cipher.decrypt(_pad(data[48:]))
    return result

if len(sys.argv) != 3:
    print('Usage: quasar_analyze.py [ENCRYPTIONKEY] [DATA_TO_DECODE]')
    sys.exit(1)

ENCRYPTIONKEY = sys.argv[1]
ENC_HOST = sys.argv[2].encode()

# Hard-coded Salt
salt = binascii.unhexlify(b'BFEB1E56FBCD973BB219022430A57843003D5644D21E62B9D4F180E7E6C33941')

# Generating AES key using PBKDF2 algorithm
AES_KEY = PBKDF2(ENCRYPTIONKEY, salt, 50000).read(16)

# Printing the decoded data
decoded = decode_data(ENC_HOST, AES_KEY, AES.MODE_CBC)
print(str(binascii.hexlify(decoded), 'utf-8'))
