#! /usr/bin/python
from __future__ import absolute_import
from __future__ import division, print_function, unicode_literals

import os
import stat
import binascii
import struct
try:
    import configparser
except ImportError:
    import ConfigParser as configparser

"""

The master key handling is really simplistic right now.
It's slow and dumb, but it works and is easy to debug.

add_master_key will create a new key called "keyid.key" in the
master_keys directory, it then calls refresh_master_keys.

refresh_master_keys will scan the master_keys directory and sort the
key files by modification time.  If there are more than
MAX_MASTER_KEYS files in the directory the oldest ones will be
removed, and the rest of the keys will be loaded.

get_master_keys calls refresh_master_key and returns a list of
(keyid, key) tuples sorted by modification time.

get_master_key gets the most recent master (keyid, key) tuple.

A future version could use a thread which uses inotify to be notified
if any of the keys have changed so that it doesn't have to reread all
the keys every time the keys are used.

"""

class ServerHelper(object):
    INI_FILE = 'server.ini'
    MAX_MASTER_KEYS = 3

    def __init__(self):
        config = configparser.RawConfigParser(
            allow_no_value = True)
        config.read(self.INI_FILE)

        if 1:
            import sys
            config.write(sys.stdout)

        self.master_keys_dir   = config.get('DEFAULT', 'master_keys_dir')

        self.ntske_port        = config.get('ntske', 'port')
        self.ntske_root_ca     = config.get('ntske', 'root_ca')
        self.ntske_server_cert = config.get('ntske', 'server_cert')
        self.ntske_server_key  = config.get('ntske', 'server_key')

        self.ntpv4_server      = config.get('ntpv4', 'server')
        self.ntpv4_port        = config.get('ntpv4', 'port')

        if not os.path.isdir(self.master_keys_dir):
            os.makedirs(self.master_keys_dir)

        self.refresh_master_keys()
        if not self._master_keys:
            self.add_master_key()

    def add_master_key(self):
        while 1:
            keyid = struct.unpack('>H', os.urandom(2))
            path = os.path.join(self.master_keys_dir, '%04x.key' % keyid)

            # We could actually get a keyid collision, retry if that happens
            if not os.path.exists(path):
                break

        key = os.urandom(32)

        with open(path + '+', 'w') as f:
            f.write('%s\n' % binascii.hexlify(key).decode('ascii'))
        os.rename(path + '+', path)

        self.refresh_master_keys()

    def refresh_master_keys(self):
        a = []
        for fn in os.listdir(self.master_keys_dir):
            if fn.endswith('.key'):
                keyid = int(fn[:-4], 16)
                path = os.path.join(self.master_keys_dir, fn)
                st = os.stat(path)
                a.append((st[stat.ST_MTIME], keyid, path))

        # Delete all but the last three keys
        while len(a) > self.MAX_MASTER_KEYS:
            os.unlink(a[0][2])
            del a[0]

        keys = []
        for mtime, keyid, path in a:
            keyvalue = bytes(binascii.unhexlify(open(path).read().strip()))
            keys.append((keyid, keyvalue))

        if 1:
            print("master keys [ %s ]" % ', '.join(
                [ str("0x%04x (%u)" % (k,k)) for k, v in keys ]))

        self._master_keys = keys

    def get_master_keys(self):
        self.refresh_master_keys()
        return self._master_keys

    def get_master_key(self):
        return self.get_master_keys()[-1]

if __name__ == '__main__':
    sh = ServerHelper()
    sh.add_master_key()
