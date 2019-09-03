#! /usr/bin/python3
from __future__ import absolute_import
from __future__ import division, print_function, unicode_literals

import aes_siv
import binascii

def unhexlify(s):
    return binascii.unhexlify(''.join(s.strip().split()))

def hexlify(d):
    return ' '.join([ binascii.hexlify(d[i:i+4]) for i in range(0, len(d), 4) ])


key = unhexlify('''fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0
               f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff''')

ad = unhexlify('''10111213 14151617 18191a1b 1c1d1e1f
              20212223 24252627''')

nonce = unhexlify('''09f91102 9d74e35b d84156c5 635688c0''')

plaintext = unhexlify('''74686973 20697320 736f6d65 20706c61
                         696e7465 78742074 6f20656e 63727970
                         74207573 696e6720 5349562d 414553''')

aead = aes_siv.AES_SIV()

ciphertext = aead.encrypt(key, nonce, plaintext, ad)

print(hexlify(ciphertext))
