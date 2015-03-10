"""Functions and classes for reading DNS records."""

import collections


class DnsRecord(collections.namedtuple('DnsRecord',
                                       ['fqdn', 'cls', 'type', 'value'])):
  pass


def from_dump(f):
  """Read DNS records from DNS record dump."""
  while True:
    l = f.readline()
    if not l:
      break
    yield DnsRecord(*l.split())
