"""Miscellaneous utility functions and classes."""

import collections
import struct


class DataChunk(collections.namedtuple('DataChunk', ['data', 'offset'])):
  pass


def ipv4_to_bytes(addr):
  return ipv4_to_chunk(addr)[0]

def ipv4_to_chunk(addr):
  octets = addr.split('.')
  if len(octets) != 4:
    return False
  octets = list(map(int, octets))
  # Every octet must fall in range [0,255]
  assert len(octets) == 4
  for o in octets:
    if not 0 <= o <= 255:
      return False
  length = (octets[0] >> 6) & 0x3
  offset = (octets[0] & 0x3f) * 3
  data = b''.join(map(lambda x: struct.pack('!B', x), octets[1:length+1]))
  return DataChunk(data, offset)
