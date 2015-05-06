"""VPN over DNS protocol utilities."""

import regex
import struct
from vodreassembler import util

DEFAULT_FQDN_SUFFIX = 'tun.vpnoverdns.com.'


def ipv4_to_bytes(addr):
  return ipv4_to_chunk(addr)[0]

def ipv4_to_chunk(addr):
  octets = addr.split('.')
  if len(octets) != 4:
    raise ValueError('IPv4 addresses must have 4 octets')
  octets = list(map(int, octets))
  # Every octet must fall in range [0,255]
  assert len(octets) == 4
  for i, o in enumerate(octets):
    if not 0 <= o <= 255:
      raise ValueError('Octet {} is {};'
                       'must be an integer within [0,255]'.format(i+1, o))
  length = (octets[0] >> 6) & 0x3
  offset = (octets[0] & 0x3f) * 3
  data = b''.join(map(lambda x: struct.pack('!B', x), octets[1:length+1]))
  return util.DataChunk(data, offset)

def normalize_fqdn_suffix(fqdn_suffix):
  if not fqdn_suffix.endswith('.'):
    fqdn_suffix += '.'
  if fqdn_suffix.startswith('.'):
    fqdn_suffix = fqdn_suffix[1:]
  return fqdn_suffix


class DnsRecordParser:
  def __init__(self, fqdn_suffix=None):
    self._suffix = normalize_fqdn_suffix(fqdn_suffix or DEFAULT_FQDN_SUFFIX)
    self._re = regex.compile(
        r'''^\s*
              ((?P<var>\w+)-(?P<value>\w+)\.)+  # variables
              v(?P<version>\w+)\.               # version
              {!s}                              # suffix
            \s*$'''.format(regex.escape(self._suffix)),
        regex.VERSION1 | regex.VERBOSE)

  def parse(self, record):
    m = self._re.fullmatch(record.fqdn)
    if not m:
      raise ValueError(
          "fqdn '{}' is not in the expected format".format(record.fqdn))
    return (m.group('version'),
            dict(zip(m.captures('var'), m.captures('value'))),
            ipv4_to_chunk(record.value))

