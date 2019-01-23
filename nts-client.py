#! /usr/bin/python
from __future__ import absolute_import
from __future__ import division, print_function, unicode_literals

import os
import sys
import struct
import socket
import rfc7822
import binascii

import aes_siv

from ntp import NTPPacket, NTPExtensionField,  NTPExtensionFieldType
from nts import NTSClientPacket, NTSCookie
from constants import *

def main():
    try:
        import configparser
    except ImportError:
        import ConfigParser as configparser

    config = configparser.RawConfigParser()
    config.read('client.ini')

    nts_server = config.get('ntpv4', 'server').strip()
    nts_port = int(config.get('ntpv4', 'port'))

    if len(sys.argv) > 1:
        nts_server = sys.argv[1]
    if len(sys.argv) > 2:
        nts_port = int(sys.argv[2])

    c2s_key = binascii.unhexlify(config.get('keys', 'c2s'))
    s2c_key = binascii.unhexlify(config.get('keys', 's2c'))

    cookies = [ binascii.unhexlify(v) for k, v in sorted(config.items('cookies')) ]
    assert cookies

    import socket
    import os

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1)

    cookie_len = len(cookies[0])

    req = NTSClientPacket()
    req.transmit_timestamp = struct.unpack('Q', os.urandom(8))[0]

    unique_identifier = os.urandom(32)

    req.ext.append(NTPExtensionField(
        NTPExtensionFieldType.Unique_Identifier,
        unique_identifier))

    req.ext.append(NTPExtensionField(
        NTPExtensionFieldType.NTS_Cookie,
        cookies[0]))

    del cookies[0]

    if 1:
        # Throw away some of the cookies for testing
        cookies = cookies[:3]

    nr_cookies = len(cookies)

    req.pack_key = c2s_key
    req.enc_ext = [ ]

    for i in range(8 - nr_cookies - 1):
        req.ext.append(NTPExtensionField(NTPExtensionFieldType.NTS_Cookie_Placeholder, bytes(bytearray(cookie_len))))

    buf = req.pack()

    if 1:
        print(NTPPacket.unpack(buf))
        print()

    if 0:
        print(NTSServerPacket.unpack(buf, unpack_key = c2s_key))
        print()

    nts_addr = (nts_server, nts_port)
    print(nts_addr)
    sock.sendto(buf, nts_addr)

    try:
        data, addr = sock.recvfrom(65536)
    except socket.timeout:
        print("Timeout")
        return

    resp = NTSClientPacket.unpack(data, unpack_key = s2c_key)
    print(resp)

    assert resp.origin_timestamp == req.transmit_timestamp
    assert resp.unique_identifier == unique_identifier

    print("nts_cookies", len(resp.nts_cookies))
    print("enc_ext", len(resp.enc_ext))
    print("unath_ext", len(resp.unauth_ext))

    cookies.extend(resp.nts_cookies)

    config.remove_section('cookies')
    config.add_section('cookies')
    for k, v in enumerate(cookies):
        config.set('cookies', str(k), binascii.hexlify(v).decode('ascii'))

    with open('client.ini', 'w') as f:
        config.write(f)

if __name__ == '__main__':
    main()
