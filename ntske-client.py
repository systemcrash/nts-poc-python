#! /usr/bin/python3
from __future__ import division, print_function, unicode_literals

import sys
import socket
import binascii
import struct
import util

from sslwrapper import SSLWrapper
from ntske_record import *
from nts import *

assert sys.version_info[0] == 3

NTS_ALPN_PROTO_B = NTS_ALPN_PROTO.encode('ASCII')

def main(argv):
    argi = 1

    use_ke_workaround = False
    disable_verify = False
    ca = '/etc/ssl/certs/ca-certificates.crt'
    verify_host = None
    strict = False

    while argv[argi].startswith('-'):
        opts = argv[argi][1:]
        argi += 1
        for o in opts:
            if o == 'k':
                use_ke_workaround = True
            elif o == 'v':
                disable_verify = True
            elif o == 'c':
                ca = argv[argi]
                argi += 1
            elif o == 'h':
                verify_host = argv[argi]
                argi += 1
            elif o == 's':
                strict = True
            else:
                print("unknown option %s" % repr(o), file = sys.stderr)
                sys.exit(1)

    if argi + 2 != len(sys.argv):
        print("Usage: python [-kv] ntske_client.py <host> <port>",
              file=sys.stderr)
        sys.exit(1)

    host = argv[argi]
    argi += 1
    port = int(argv[argi])
    argi += 1

    if verify_host is None:
        verify_host = host

    wrapper = SSLWrapper()
    wrapper.client(ca, disable_verify)
    wrapper.set_alpn_protocols([NTS_ALPN_PROTO])

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    s = wrapper.connect(sock, verify_host)

    proto = s.selected_alpn_protocol()
    if proto != NTS_ALPN_PROTO:
        msg = "failed to negotiate ALPN proto, expected %s, got %s, continuing anyway" % (
            repr(NTS_ALPN_PROTO), repr(proto))
        if strict:
            raise IOError(msg)
        else:
            print("WARNING:", msg, file = sys.stderr)

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

    s.sendall(b''.join(map(bytes, records)))

    npn_ack = False
    aead_ack = False
    cookies = list()

    ntpv4_server = None
    ntpv4_port = None

    eom = False

    do_shutdown = False

    while True:
        try:
            resp = s.recv(4)
        except socket.timeout:
            if eom:
                print("timeout but EOM seen, continuing", file = sys.stderr)
                break
            raise IOError("timeout but no EOM seen")

        if resp is None:
            if eom:
                print("ragged EOF but EOM seen, continuing", file = sys.stderr)
                break
            raise IOError("ragged EOF no EOM seen")

        elif not resp:
            if eom:
                do_shutdown = True
                break
            raise IOError("EOF but no EOM seen")

        if len(resp) < 4:
            raise IOError("short packet")

        body_len = struct.unpack(">H", resp[2:4])[0]
        if body_len > 0:
            resp += s.recv(body_len)
        record = Record(resp)
        print(record.critical, record.rec_type, repr(record.body), repr(resp))
        if record.rec_type == RT_END_OF_MESSAGE:
            eom = True
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

    if not npn_ack:
        print("No NPN record in server response", file=sys.stderr)
        return 1
    if not aead_ack:
        print("No AEAD record in server response", file=sys.stderr)
        return 1
    if len(cookies) == 0:
        print("No cookies provided in server response", file=sys.stderr)
        return 1

    key_label = NTS_TLS_Key_Label
    if use_ke_workaround:
        key_label = NTS_TLS_Key_Label_Workaround

    c2s_key = s.export_keying_material(key_label, NTS_TLS_Key_LEN, NTS_TLS_Key_C2S)
    s2c_key = s.export_keying_material(key_label, NTS_TLS_Key_LEN, NTS_TLS_Key_S2C)

    if do_shutdown:
        s.shutdown()

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
