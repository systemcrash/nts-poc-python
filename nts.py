#! /usr/bin/python
from __future__ import absolute_import
from __future__ import division, print_function, unicode_literals

from ntp import *

import os
import aes_siv

"""
TODO would it be better to add flags to the NTPExtensionField indicating the status of the fields?

.nts_authenticated - true if authenticated using NTS
.nts_encrypted - true if it was part of the NTS_Authentication field

or maybe it should be an enum

"""

class NTSCookie(object):
    HEADER_FMT = '>H'
    HEADER_LEN = struct.calcsize(HEADER_FMT)
    NONCE_LEN = 16
    KEY_LEN = 32

    PLAINTEXT_FMT = '>H32s32s'
    PLAINTEXT_LEN = struct.calcsize(PLAINTEXT_FMT)

    AEAD_EXTRA_LEN = 16
    CIPHERTEXT_LEN = PLAINTEXT_LEN + AEAD_EXTRA_LEN
    COOKIE_LEN = HEADER_LEN + NONCE_LEN + CIPHERTEXT_LEN

    def __init__(self):
        self.aead = aes_siv.AES_SIV()

    def unpack(self, keys, cookie):
        assert len(cookie) == self.COOKIE_LEN

        keyid = struct.unpack_from(self.HEADER_FMT, cookie, 0)[0]

        key = keys[keyid]

        nonce = cookie[self.HEADER_LEN : self.HEADER_LEN + self.NONCE_LEN]
        ciphertext = cookie[self.HEADER_LEN + self.NONCE_LEN:]

        plaintext = self.aead.decrypt(key, nonce, ciphertext, b'')

        aead_algo, s2c_key, c2s_key = struct.unpack(self.PLAINTEXT_FMT, plaintext)

        if 0:
            print("aead_algo  %u" % (aead_algo))
            print("s2c_key    %u %s" % (len(s2c_key), binascii.hexlify(s2c_key)))
            print("c2s_key    %u %s" % (len(c2s_key), binascii.hexlify(c2s_key)))

        return keyid, aead_algo, s2c_key, c2s_key

    def pack(self, keyid, key, aead_algo, s2c_key, c2s_key):
        header = struct.pack(self.HEADER_FMT, keyid)

        if 0:
            print("aead_algo  %u" % (aead_algo))
            print("s2c_key    %u %s" % (len(s2c_key), binascii.hexlify(s2c_key)))
            print("c2s_key    %u %s" % (len(c2s_key), binascii.hexlify(c2s_key)))

        nonce = os.urandom(self.NONCE_LEN)

        plaintext = struct.pack(self.PLAINTEXT_FMT, aead_algo, s2c_key, c2s_key)

        ciphertext = bytes(self.aead.encrypt(key, nonce, plaintext, b''))

        cookie = header + nonce + ciphertext

        return cookie

class NTSPacket(NTPPacket):
    def __init__(self, unpack_key = None, pack_key = None,  *args, **kwargs):
        NTPPacket.__init__(self, *args, **kwargs)
        self.unpack_key = unpack_key
        self.pack_key = pack_key
        self.enc_ext = None
        self.unauth_ext = None
        self.aead = None
        self.unique_identifier = None

    def get_aead(self):
        if self.aead is None:
            self.aead = aes_siv.AES_SIV()
        return self.aead

    def get_keyenc(self):
        return self.get_aead()

    def handle_authenticator(self, field, buf, offset):
        assert self.enc_ext is None
        self.enc_ext = []

        aead = self.get_aead()

        nonce_len, enc_len = struct.unpack_from('>HH', field.value, 0)
        i = 4
        nonce = field.value[i : i + nonce_len]
        i = (i + nonce_len + 3) & ~3
        ciphertext = field.value[i : i + enc_len]
        i = (i + nonce_len + 3) & ~3
        assert i <= len(field.value)

        if 0:
            print("key   %u %s" % (len(self.unpack_key), binascii.hexlify(self.unpack_key)))
            print("nonce %u %s" % (len(nonce), binascii.hexlify(nonce)))
            print("enc   %u %s" % (len(ciphertext), binascii.hexlify(ciphertext)))
            print("add   %u %s" % (len(buf[:offset]), binascii.hexlify(buf[:offset])))

        plaintext = bytes(aead.decrypt(self.unpack_key, nonce, ciphertext, buf[:offset]))
        assert(plaintext is not None)

        offset = 0
        remain = len(plaintext)
        while remain:
            field_type, field_len = NTPExtensionField.peek(plaintext, offset)
            assert field_len >= 4
            assert field_len % 4 == 0

            field = NTPExtensionField(field_type,
                                      plaintext[offset + 4 : offset + field_len])

            if field.field_type == NTPExtensionFieldType.NTS_Cookie:
                # assert len(self.nts_cookies) < 8
                self.nts_cookies.append(field.value)

            elif field.field_type == NTPExtensionFieldType.NTS_Cookie_Placeholder:
                self.nr_cookie_placeholders += 1

            self.enc_ext.append(field)

            remain -= field_len
            offset += field_len

        assert remain == 0

        self.unauth_ext = []

    def handle_field(self, field, buf, offset):
        if field.field_type == NTPExtensionFieldType.Unique_Identifier:
            assert self.unique_identifier is None
            self.unique_identifier = field.value
            self.ext.append(field)

        else:
            self.ext.append(field)

    def pack(self):
        buf = super(NTSPacket, self).pack()
        if self.enc_ext is not None:
            plaintext = b''.join([ _.pack() for _ in self.enc_ext ])
            aead = self.get_aead()
            nonce = os.urandom(16)

            if 0:
                print("key    %u %s" % (len(self.pack_key), binascii.hexlify(self.pack_key)))
                print("nonce  %u %s" % (len(nonce), binascii.hexlify(nonce)))
                print("add    %u %s" % (len(buf), binascii.hexlify(buf)))
                print("plain  %u %s" % (len(plaintext), binascii.hexlify(plaintext)))

            ciphertext = bytes(aead.encrypt(self.pack_key, nonce, plaintext, buf))

            if 0:
                print("cipher %u %s" % (len(ciphertext), binascii.hexlify(ciphertext)))

            assert len(nonce) % 4 == 0
            assert len(ciphertext) % 4 == 0

            a = [
                struct.pack('>HH', len(nonce), len(ciphertext)),
                nonce,
                ciphertext,
                ]

            auth = NTPExtensionField(
                NTPExtensionFieldType.NTS_Authenticator,
                b''.join(a))

            buf += auth.pack(last = True)

        return buf

class NTSServerPacket(NTSPacket):
    def __init__(self, keys = {}, *args, **kwargs):
        NTSPacket.__init__(self, *args, **kwargs)
        self.nr_cookie_placeholders = 0
        self.nts_cookie = None
        self.keys = keys

    def handle_field(self, field, buf, offset):
        if self.unauth_ext is not None:
            self.unauth_ext.append(field)

        elif field.field_type == NTPExtensionFieldType.NTS_Cookie:
            assert self.nts_cookie is None
            self.nts_cookie = field.value

            if self.unpack_key:
                return

            self.nts_keyid, self.aead_algo, self.pack_key, self.unpack_key = NTSCookie().unpack(self.keys, field.value)

            assert self.aead_algo == 15

        elif field.field_type == NTPExtensionFieldType.NTS_Cookie_Placeholder:
            self.nr_cookie_placeholders += 1

        elif field.field_type == NTPExtensionFieldType.NTS_Authenticator:
            self.handle_authenticator(field, buf, offset)

        else:
            super(NTSServerPacket, self).handle_field(field, buf, offset)

class NTSClientPacket(NTSPacket):
    def __init__(self, *args, **kwargs):
        NTSPacket.__init__(self, *args, **kwargs)
        self.nts_cookies = []

    def handle_field(self, field, buf, offset):
        if self.unauth_ext is not None:
            self.unauth_ext.append(field)

        elif field.field_type == NTPExtensionFieldType.NTS_Cookie:
            raise ValueError("NTS Cookie in plain text")

        elif field.field_type == NTPExtensionFieldType.NTS_Cookie_Placeholder:
            raise ValueError("NTS Cookie Placeholder in client package")

        elif field.field_type == NTPExtensionFieldType.NTS_Authenticator:
            self.handle_authenticator(field, buf, offset)

        else:
            super(NTSClientPacket, self).handle_field(field, buf, offset)
