#! /usr/bin/python3
from __future__ import division, print_function, unicode_literals

import os
import sys
import socket
import binascii
import struct
import OpenSSL
import traceback
from OpenSSL import SSL

from aes_siv import AES_SIV
from rfc5705 import export_keying_materials
from constants import *
from ntske_record import *
from nts import NTSCookie
from server_helper import ServerHelper

CIPHERS = [
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES128-GCM-SHA256'
    'ECDHE-ECDSA-AES128-GCM-SHA256',
    ]

# Protocol IDs, see the IANA Network Time Security Next Protocols registry
SUPPORTED_PROTOCOLS = {
    0,                                  # NTPv4
    }

# Algorithm identifiers, see RFC5297
SUPPORTED_ALGORITHMS = {
    15,                                 # AEAD_AES_SIV_CMAC_256
    }

def unpack_array(buf):
    assert(len(buf) % 2 == 0)
    fmt = '>%uH' % (len(buf) / 2)
    return struct.unpack(fmt, buf)

def pack_array(a):
    if len(a) == 0:
        return b''
    elif len(a) == 1:
        return struct.pack('>H', a[0])
    else:
        return struct.pack('>%uH' % len(a), fmt, a)

class NTSKEServer(object):
    def __init__(self):
        self.ntpv4_server = None
        self.ntpv4_port = None

class NTSKESession(object):
    def __init__(self, server, keyid, key):
        self.server = server
        self.keyid = keyid
        self.key = key

        self.npn_protocols = None
        self.aead_algorithms = None
        self.eom_received = False

        self.errors = set()
        self.warnings = set()

    def error(self, code, message):
        print("error %u: %s" % (code, message), file = sys.stderr)
        self.errors.add(code)

    def warning(self, code, message):
        print("warning %u: %s" % (code, message), file = sys.stderr)
        self.warnings.add(code)

    def notice(self, message):
        print(message, file = sys.stderr)

    def process_record(self, record):
        print(record.critical, record.rec_type, record.body)

        if self.eom_received:
            self.error(ERR_BAD_REQUEST, "Records received after EOM")
            return

        if record.rec_type == RT_END_OF_MESSAGE:
            if not record.critical:
                self.error(ERR_BAD_REQUEST,
                           "EOM record MUST be criticial")
                return

            if len(record.body):
                self.error(ERR_BAD_REQUEST,
                           "EOM record should have zero length body")
                return

            self.eom_received = True

        elif record.rec_type == RT_NEXT_PROTO_NEG:
            if self.npn_protocols:
                self.error(ERR_BAD_REQUEST, "Duplicate NPN record")
                return

            if not record.critical:
                self.error(ERR_BAD_REQUEST, "NPN record MUST be criticial")
                return

            if not len(record.body):
                self.error(ERR_BAD_REQUEST,
                           "NPN record MUST specify at least one protocol")
                return

            if len(record.body) % 2:
                self.error(ERR_BAD_REQUEST,
                           "NPN record has invalid length")
                return

            self.npn_protocols = unpack_array(record.body)

        elif record.rec_type == RT_AEAD_NEG:
            if self.aead_algorithms:
                self.error(ERR_BAD_REQUEST, "Duplicate AEAD record")
                return

            if not len(record.body):
                self.error(ERR_BAD_REQUEST,
                           "AEAD record MUST specify at least one algorithm")
                return

            if len(record.body) % 2:
                self.error(ERR_BAD_REQUEST,
                           "AEAD record has invalid length")
                return

            self.aead_algorithms = unpack_array(record.body)

        elif record.rec_type == RT_ERROR:
            self.error(ERR_BAD_REQUEST, "Received error record")

        elif record.rec_type == RT_WARNING:
            self.error(ERR_BAD_REQUEST, "Received warning record")

        elif record.rec_type == RT_NEW_COOKIE:
            self.error(ERR_BAD_REQUEST, "Received new cookie record")

        else:
            if record.critical:
                self.error(ERR_UNREC_CRIT, "Received unknown record %u" % (
                    record.rec_type))
            else:
                self.notice("Received unknown record %u" % (record.rec_type))

    def get_response(self, c2s_key, s2c_key):
        protocols = []
        if self.npn_protocols is None:
            self.error(ERR_BAD_REQUEST, "No NPN record received")
        else:
            for protocol in self.npn_protocols:
                if protocol in SUPPORTED_PROTOCOLS:
                    protocols.append(protocol)
                else:
                    self.notice("Unknown protocol %u" % protocol)

        algorithms = []
        if self.aead_algorithms is None:
            self.error(ERR_BAD_REQUEST, "No AEAD record received")
        else:
            for algorithm in self.aead_algorithms:
                if algorithm in SUPPORTED_ALGORITHMS:
                    algorithms.append(algorithm)
                else:
                    self.notice("Unknown algorithm %u" % algorithm)

        if not self.eom_received:
            self.error(ERR_BAD_REQUEST, "No EOM record received")

        records = []

        for code in sorted(self.errors):
            records.append(Record.make(True, RT_ERROR, struct.pack(">H", code)))

        for code in sorted(self.warnings):
            records.append(Record.make(True, RT_WARNING, struct.pack(">H", code)))

        if self.errors:
            return records

        print("C2S: " + binascii.hexlify(c2s_key).decode('utf-8'))
        print("S2C: " + binascii.hexlify(s2c_key).decode('utf-8'))

        protocol = protocols[0]
        aead_algo = algorithms[0]

        records.append(Record.make(True, RT_NEXT_PROTO_NEG,
                                   struct.pack('>H', protocol)))

        records.append(Record.make(True, RT_AEAD_NEG,
                                   struct.pack('>H', aead_algo)))

        if self.server.ntpv4_server is not None:
            records.append(Record.make(True, RT_NTPV4_SERVER,
                                       self.server.ntpv4_server))

        if self.server.ntpv4_port is not None:
            records.append(Record.make(True, RT_NTPV4_PORT,
                                  struct.pack(">H", self.server.ntpv4_port)))

        for i in range(8):
            cookie = NTSCookie().pack(
                self.keyid, self.key,
                aead_algo, s2c_key, c2s_key)
            records.append(Record.make(False, RT_NEW_COOKIE, cookie))

        records.append(Record.make(True, RT_END_OF_MESSAGE))

        return records

def handle(server, ssl, addr, keyid, key):
    session = NTSKESession(server, keyid, key)

    print('Connection from %s' % repr(addr))

    ssl.do_handshake()

    if ssl.get_alpn_proto_negotiated() != NTS_ALPN_PROTO:
        raise IOError("Failed to negotiate ntske/1")

    npn_ack = False
    aead_ack = False
    protocols = []

    while True:
        resp = ssl.recv(4)
        if(len(resp) < 4):
            print("Premature end of server response", file=sys.stderr)
            return 1
        body_len = struct.unpack(">H", resp[2:4])[0]
        if body_len > 0:
            resp += ssl.recv(body_len)
        record = Record(resp)
        session.process_record(record)
        if record.rec_type == RT_END_OF_MESSAGE:
            break

    c2s_key = ssl.export_keying_material(NTS_TLS_Key_Label, NTS_TLS_Key_LEN, NTS_TLS_Key_C2S)
    s2c_key = ssl.export_keying_material(NTS_TLS_Key_Label, NTS_TLS_Key_LEN, NTS_TLS_Key_S2C)

    response = session.get_response(c2s_key, s2c_key)

    ssl.sendall(b''.join(map(bytes, response)))

def main():
    serverhelper = ServerHelper()

    server = NTSKEServer()
    if serverhelper.ntpv4_server:
        server.ntpv4_server = serverhelper.ntpv4_server.encode('ascii')
    else:
        server.ntpv4_server = None
    if serverhelper.ntpv4_port:
        server.ntpv4_port = int(serverhelper.ntpv4_port)
    else:
        server.ntpv4_port = None

    def alpn_select_callback(ssl, options):
        return NTS_ALPN_PROTO

    def verify_callback(ssl, cert, errno, depth, result):
        if result == 0:
            return False
        if depth == 0:
            #FIXME: check hostname
            pass
        return True

    ctx = SSL.Context(SSL.SSLv23_METHOD)
    ctx.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 |
                    SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1)
    print(list(map(str, CIPHERS)))
    ctx.set_cipher_list(':'.join(CIPHERS).encode('ASCII'))
    ctx.load_verify_locations(serverhelper.ntske_root_ca)
    ctx.use_certificate_file(serverhelper.ntske_server_cert)
    ctx.use_privatekey_file(serverhelper.ntske_server_key)
    ctx.set_verify(SSL.VERIFY_PEER, verify_callback)
    ctx.set_alpn_select_callback(alpn_select_callback)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    ssl_server = SSL.Connection(ctx, sock)
    ssl_server.bind(('', int(serverhelper.ntske_port)))
    ssl_server.listen(3)

    while True:
        try:
            ssl, addr = ssl_server.accept()
        except KeyboardInterrupt:
            break
        except Exception:
            traceback.print_exc()

        keyid, key = serverhelper.get_master_key()

        try:
            handle(server, ssl, addr, keyid, key)
        except KeyboardInterrupt:
            break
        except Exception:
            traceback.print_exc()
        finally:
            ssl.close()

    print()
    print("Shutting down")

if __name__ == "__main__":
    main()
