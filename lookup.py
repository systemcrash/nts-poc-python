#! /usr/bin/python3
from __future__ import division, print_function, unicode_literals

import sys
import dns, dns.resolver

def lookup_a_records(fqdn):
    return sorted(dns.resolver.query(fqdn, 'A'),
                  key = lambda r: r.address)

def lookup_srv_records(fqdn):
    return sorted(dns.resolver.query(fqdn, 'SRV'),
                  key = lambda r: (r.priority, -r.weight, r.target))

def lookup_ntske_srv_records(fqdn):
    return lookup_srv_records('_ntske._tcp.' + fqdn)

def main():
    if len(sys.argv) <= 1:
        print ("Usage: %s [fqdn...]" % sys.argv[0], file = sys.stderr)
        sys.exit(1)

    for fqdn in sys.argv[1:]:

        print("NTP servers")
        try:
            for r in lookup_a_records(fqdn):
                print("    %s" % r.address)
        except dns.resolver.NXDOMAIN:
            print("   None")
        print()

        print("NTS servers")
        try:
            # Notice that we need to trim the trailing period of FQDNs
            for r in lookup_ntske_srv_records(fqdn):
                print("    %s:%u" % (str(r.target).rstrip('.'), r.port))
        except dns.resolver.NXDOMAIN:
            print("   None")
        print()

if __name__ == '__main__':
    if not sys.argv[0]:
        sys.argv = [ '', 'time.weinigel.se' ]
    main()



