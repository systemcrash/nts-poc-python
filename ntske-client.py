#! /usr/bin/python3
from __future__ import division, print_function, unicode_literals

import sys
import socket
import binascii
import struct
import OpenSSL

from ntske_record import *
from nts import *

def main(argv):
    if len(argv) != 4:
        print("Usage: python ntske_client.py <host> <port> <ca.pem>", file=sys.stderr)
        return 2

    host = argv[1]
    port = argv[2]
    ca_pem = argv[3]

    def verify_callback(conn, cert, errno, depth, result):
        if result == 0:
            return False
        if depth == 0:
            #FIXME: check hostname
            pass
        return True

    ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
    ctx.set_options(OpenSSL.SSL.OP_NO_SSLv2 |
                    OpenSSL.SSL.OP_NO_SSLv3 |
                    OpenSSL.SSL.OP_NO_TLSv1 |
                    OpenSSL.SSL.OP_NO_TLSv1_1)
    ctx.set_cipher_list(b"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256")
    ctx.load_verify_locations(ca_pem)
    ctx.set_verify(OpenSSL.SSL.VERIFY_PEER, verify_callback)
    ctx.set_alpn_protos([NTS_ALPN_PROTO])

    addrs = socket.getaddrinfo(host, int(port), socket.AF_INET, socket.SOCK_STREAM)
    if len(addrs) == 0:
        print("Host not found", file=sys.stderr)
        return 1
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl = OpenSSL.SSL.Connection(ctx, sock)
    ssl.set_tlsext_host_name(host.encode("utf-8"))
    ssl.connect(addrs[0][4])
    ssl.do_handshake()
    if ssl.get_alpn_proto_negotiated() != NTS_ALPN_PROTO:
        print("Failed to negotiate ntske/1", file=sys.stderr)
        return 1

    records = []

    npn_neg = Record()
    npn_neg.critical = True
    npn_neg.rec_type = RT_NEXT_PROTO_NEG
    npn_neg.body = struct.pack(">H", 0)
    records.append(npn_neg)

    aead_neg = Record()
    aead_neg.critical = True
    aead_neg.rec_type = RT_AEAD_NEG
    aead_neg.body = struct.pack(">H", 15)
    records.append(aead_neg)

    eom = Record()
    eom.critical = True
    eom.rec_type = RT_END_OF_MESSAGE
    eom.body = b''
    records.append(eom)

    ssl.sendall(b''.join(map(bytes, records)))

    npn_ack = False
    aead_ack = False
    cookies = list()

    ntpv4_server = None
    ntpv4_port = None

    while True:
        resp = ssl.recv(4)
        if(len(resp) < 4):
            print("Premature end of server response", file=sys.stderr)
            return 1
        body_len = struct.unpack(">H", resp[2:4])[0]
        if body_len > 0:
            resp += ssl.recv(body_len)
        record = Record(resp)
        print(record.critical, record.rec_type, record.body)
        if record.rec_type == RT_END_OF_MESSAGE:
            break
        elif record.rec_type == RT_NEXT_PROTO_NEG:
            if npn_ack:
                print("Duplicate NPN record", file=sys.stderr)
                return 1
            if record.body != struct.pack(">H", 0):
                print("Unacceptable NPN response", file=sys.stderr)
                return 1
            npn_ack = True
        elif record.rec_type == RT_ERROR:
            print("Received error response", file=sys.stderr)
            return 1
        elif record.rec_type == RT_WARNING:
            print("Received warning response (aborting)", file=sys.stderr)
            return 1
        elif record.rec_type == RT_AEAD_NEG:
            if aead_ack:
                print("Duplicate AEAD record", file=sys.stderr)
                return 1
            if record.body != struct.pack(">H", 15):
                print("Unacceptable AEAD response", file=sys.stderr)
                return 1
            aead_ack = True
        elif record.rec_type == RT_NEW_COOKIE:
            cookies.append(record.body)
        elif record.rec_type == RT_NTPV4_SERVER:
            ntpv4_server = record.body
        elif record.rec_type == RT_NTPV4_PORT:
            ntpv4_port = struct.unpack(">H", record.body)[0]
        else:
            if record.critical:
                print("Unrecognized critical record", file=sys.stderr)
                return 1

    ssl.shutdown()

    if not npn_ack:
        print("No NPN record in server response", file=sys.stderr)
        return 1
    if not aead_ack:
        print("No AEAD record in server response", file=sys.stderr)
        return 1
    if len(cookies) == 0:
        print("No cookies provided in server response", file=sys.stderr)
        return 1

    c2s_key = ssl.export_keying_material(NTS_TLS_Key_Label, NTS_TLS_Key_LEN, NTS_TLS_Key_C2S)
    s2c_key = ssl.export_keying_material(NTS_TLS_Key_Label, NTS_TLS_Key_LEN, NTS_TLS_Key_S2C)

    print("C2S: " + binascii.hexlify(c2s_key).decode('utf-8'))
    print("S2C: " + binascii.hexlify(s2c_key).decode('utf-8'))
    for cookie in cookies:
        print("Cookie: " + binascii.hexlify(cookie).decode('utf-8'))

    if ntpv4_server:
        ntpv4_server = ntpv4_server.decode('ASCII')
    else:
        ntpv4_server = host

    if ntpv4_port:
        ntpv4_port = int(ntpv4_port)
    else:
        ntpv4_port = NTPV4_DEFAULT_PORT

    import configparser
    config = configparser.RawConfigParser()
    config.read('client.ini')
    if not config.has_section('ntpv4'):
        config.add_section('ntpv4')
    config.set('ntpv4', 'server', ntpv4_server)
    config.set('ntpv4', 'port', "%u" % ntpv4_port)
    if not config.has_section('keys'):
        config.add_section('keys')
    config.set('keys', 'c2s', binascii.hexlify(c2s_key).decode('ascii'))
    config.set('keys', 's2c', binascii.hexlify(s2c_key).decode('ascii'))
    config.remove_section('cookies')
    config.add_section('cookies')
    for k, v in enumerate(cookies):
        config.set('cookies', str(k), binascii.hexlify(v).decode('ascii'))
    with open('client.ini', 'w') as f:
        config.write(f)

    return 0

if __name__ == "__main__":
    if not sys.argv[0]:
        sys.argv = [ '', 'localhost', '4443', '../ntp/nts/bin/rootCaBundle.pem' ]

    sys.exit(main(sys.argv))
