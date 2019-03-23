#! /usr/bin/python3
from __future__ import absolute_import
from __future__ import division, print_function, unicode_literals

import socket
import os
import time
import traceback
import binascii
import stat

from util import epoch_to_ntp_ts
from server_helper import ServerHelper
from constants import *
from ntp import NTPExtensionField,  NTPExtensionFieldType
from nts import NTSServerPacket, NTSCookie

def handle(req, master_key):
    ts = epoch_to_ntp_ts(time.time())

    resp = NTSServerPacket(
        mode = Mode.SERVER,
        stratum = 15,
        reference_id = b'\0\0\0\0',
        precision = -10,
        reference_timestamp = ts,
        origin_timestamp = req.transmit_timestamp,
        receive_timestamp = ts,
        transmit_timestamp = ts,
        )

    if req.unique_identifier is not None:
        resp.ext.append(NTPExtensionField(
            NTPExtensionFieldType.Unique_Identifier,
            req.unique_identifier))

    if req.enc_ext is not None:
        assert req.unique_identifier is not None

        resp.pack_key = req.pack_key
        resp.enc_ext = []

        keyid, key = master_key

        assert req.nr_cookie_placeholders <= 7

        for i in range(req.nr_cookie_placeholders + 1):
            cookie = NTSCookie().pack(
                keyid, key,
                req.aead_algo, req.pack_key, req.unpack_key)

            resp.enc_ext.append(NTPExtensionField(
                NTPExtensionFieldType.NTS_Cookie,
                cookie))

    return resp

def main():
    serverhelper = ServerHelper()

    if serverhelper.ntpv4_server:
        host = serverhelper.ntpv4_server.strip()
    else:
        host = ''

    if serverhelper.ntpv4_port:
        port = int(serverhelper.ntpv4_port)
    else:
        port = NTPV4_DEFAULT_PORT

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))

    while 1:
        try:
            data, addr = sock.recvfrom(65536)
        except socket.timeout:
            print("timeout")
            continue
        except KeyboardInterrupt:
            break
        except Exception:
            traceback.print_exc()

        print("RECV", repr(addr), len(data), repr(data))

        keys = serverhelper.get_master_keys()

        try:
            req = NTSServerPacket.unpack(data, keys = dict(keys))
            print(req)
            print()

            resp = handle(req, master_key = keys[-1])
            buf = resp.pack()
            print("RESP", len(buf), repr(buf))
            print(resp)

            sock.sendto(buf, addr)
        except KeyboardInterrupt:
            break
        except Exception:
            traceback.print_exc()

if __name__ == '__main__':
    main()
