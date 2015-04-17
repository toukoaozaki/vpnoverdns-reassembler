"""Functions and classes for reading DNS records."""

import collections


class DnsRecord(collections.namedtuple('DnsRecord',
                                       ['fqdn', 'cls', 'type', 'value'])):
  pass


def from_dump(src, filt=None):
  """Read DNS records from DNS record dump."""
  filt = filt or (lambda x: True)
  while True:
    l = src.readline()
    if not l:
      break
    record = DnsRecord(*l.split())
    if filt(record):
      yield record
