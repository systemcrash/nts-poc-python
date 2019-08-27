#! /usr/bin/python3
from __future__ import division, print_function, unicode_literals

import os
import sys
import socket
import binascii
import struct
import traceback
from socketserver import ThreadingTCPServer, TCPServer, BaseRequestHandler

from pooling import ThreadPoolTCPServer
from sslwrapper import SSLWrapper
from constants import *
from ntske_record import *
from nts import NTSCookie
from server_helper import ServerHelper

assert sys.version_info[0] == 3

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

class NTSKEHandler(BaseRequestHandler):
    def handle(self):
        print("Handle", self.client_address, "in child", os.getpid())

        self.keyid, self.key = self.server.helper.get_master_key()
        s = self.server.wrapper.accept(self.request)

        self.npn_protocols = None
        self.aead_algorithms = None
        self.eom_received = False

        self.errors = set()
        self.warnings = set()

        npn_ack = False
        aead_ack = False
        protocols = []

        while True:
            resp = s.recv(4)
            if resp is None:
                print("unexpected EOF")
                return 1
            if (len(resp) < 4):
                print("Premature end of server response", file = sys.stderr)
                return 1
            body_len = struct.unpack(">H", resp[2:4])[0]
            if body_len > 0:
                resp += s.recv(body_len)
            record = Record(resp)
            self.process_record(record)
            if record.rec_type == RT_END_OF_MESSAGE:
                break

        c2s_key = s.export_keying_material(self.server.key_label, NTS_TLS_Key_LEN, NTS_TLS_Key_C2S)
        s2c_key = s.export_keying_material(self.server.key_label, NTS_TLS_Key_LEN, NTS_TLS_Key_S2C)

        response = self.get_response(c2s_key, s2c_key)

        s.sendall(b''.join(map(bytes, response)))

        s.shutdown()

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
            records.append(Record.make(True, RT_END_OF_MESSAGE))
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

ChosenTCPServer = ThreadingTCPServer
ChosenTCPServer = ThreadPoolTCPServer

class NTSKEServer(ChosenTCPServer):
    allow_reuse_address = True

    def __init__(self, config_path):
        self.helper = ServerHelper(config_path)

        host = '0.0.0.0'
        port = int(self.helper.ntske_port)

        super(NTSKEServer, self).__init__((host, port), NTSKEHandler)

        self.ntpv4_server = self.helper.ntpv4_server
        self.ntpv4_port = self.helper.ntpv4_port
        self.key_label = self.helper.key_label

        self.wrapper = SSLWrapper()
        self.wrapper.server(self.helper.ntske_root_ca,
                            self.helper.ntske_server_cert,
                            self.helper.ntske_server_key)
        self.wrapper.set_alpn_protocols([NTS_ALPN_PROTO])

def main():
    config_path = 'server.ini'

    if len(sys.argv) > 2:
        print("Usage: %s [server.ini]" % sys.argv[0], file = sys.stderr)
        sys.exit(1)

    if len(sys.argv) > 1:
        config_path = sys.argv[1]

    server = NTSKEServer(config_path)

    pids = []

    if 1:
        for i in range(3):
            pid = os.fork()
            if pid == 0:
                print("child process", os.getpid())
                try:
                    try:
                        server.serve_forever()
                    except KeyboardInterrupt:
                        print("keyboardinterrupt in child", os.getpid(), "...")
                        pass
                    print("child", os.getpid(), "stopping...")
                    server.server_close()
                finally:
                    sys.exit(0)
            else:
                pids.append(pid)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("keyboardinterrupt")

    print("shutting down...")

    server.server_close()

    for pid in pids:
        p, status = os.wait()
        print("child", p, "has stopped")

if __name__ == "__main__":
    main()
