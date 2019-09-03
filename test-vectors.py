#! /usr/bin/python3
from __future__ import absolute_import
from __future__ import division, print_function, unicode_literals

import aes_siv
import binascii

def unhexlify(s):
    return binascii.unhexlify(''.join(s.strip().split()))

def hexlify(d):
    return ' '.join([ binascii.hexlify(d[i:i+4]) for i in range(0, len(d), 4) ])

# Test data from A.2 in https://tools.ietf.org/html/rfc5297
# with the change that ad2 is dropped.

key = unhexlify('''7f7e7d7c 7b7a7978 77767574 73727170
                   40414243 44454647 48494a4b 4c4d4e4f''')

ad = unhexlify('''00112233 44556677 8899aabb ccddeeff
                  deaddada deaddada ffeeddcc bbaa9988
                  77665544 33221100''')

nonce = unhexlify('''09f91102 9d74e35b d84156c5 635688c0''')

plaintext = unhexlify('''74686973 20697320 736f6d65 20706c61
                         696e7465 78742074 6f20656e 63727970
                         74207573 696e6720 5349562d 414553''')

aead = aes_siv.AES_SIV()

print("Key:  ", hexlify(key))
print("AD:   ", hexlify(ad))
print("Nonce:", hexlify(nonce))
print("Plain:", hexlify(plaintext))
print()

ciphertext = aead.encrypt(key, nonce, plaintext, ad)

print()
print("Out:   ", hexlify(ciphertext))
