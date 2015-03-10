"""Miscellaneous utility functions and classes."""

import struct

def ipv4_to_bytes(addr):
  octets = addr.split('.')
  if len(octets) != 4:
    return False
  octets = list(map(int, octets))
  # Every octet must fall in range [0,255]
  for o in octets:
    if not 0 <= o <= 255:
      return False
  return b''.join(map(lambda x: struct.pack('!B', x), octets))
