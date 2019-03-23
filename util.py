#! /usr/bin/python
from __future__ import division, print_function, unicode_literals

import time
import math

NTP_TS_EPOCH_OFFSET = 2208988800

def ntp_short_to_seconds(ntp_short):
    return ntp_short / 2.0 ** 16

def ntp_ts_to_epoch(ntp_ts):
    return ntp_ts / 2.0**32 - NTP_TS_EPOCH_OFFSET

def ntp_ts_to_iso(ntp_ts):
    t = ntp_ts_to_epoch(ntp_ts)
    s = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t))
    s += "%.6fZ" % (t - math.floor(t))
    return s

def epoch_to_ntp_ts(t):
    return int((t + NTP_TS_EPOCH_OFFSET) * 2.0**32)
