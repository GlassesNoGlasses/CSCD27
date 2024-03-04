BUFFER_SIZE = 1048576  # the file size is limited to 1 mb
DH_G = 5               # co-prime
DH_KEY_SIZE = 256      # bytes
DH_NONCE_SIZE = 16     # bytes
AES_KEY_SIZE = 32      # bytes

import os, socket, json

from Crypto.Util import number
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

p = number.getStrongPrime(2048, DH_G)
a = number.getRandomNBitInteger(2048)
n = get_random_bytes(16)

print(len(b'u3K4\xea,\xaa\xffe:\xb8.o\x91\xdbdMy\x11:^'))


