"""VPN over DNS protocol utilities."""

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
