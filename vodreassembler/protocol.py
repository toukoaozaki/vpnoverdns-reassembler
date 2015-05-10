"""VPN over DNS protocol utilities."""

import binascii
import collections
import enum
import itertools
import regex
import struct
from vodreassembler import util
from vodreassembler import dnsrecord

DEFAULT_FQDN_SUFFIX = 'tun.vpnoverdns.com.'


class Error(Exception):
  pass


class UnknownVersionError(Error):
  pass


def ipv4_to_bytes(addr):
  return ipv4_to_chunk(addr)[0]

def ipv4_to_chunk(addr):
  octets = addr.split('.')
  if len(octets) != 4:
    raise ValueError('IPv4 addresses must have 4 octets')
  octets = map(int, octets)
  try:
    data = ipv4_to_chunk.packer.pack(*octets)
  except struct.error as e:
    raise ValueError('every octet must be within [0,255]') from e

  length = (data[0] >> 6) & 0x3
  offset = (data[0] & 0x3f) * 3
  return util.DataChunk(data[1:length+1], offset)

ipv4_to_chunk.packer = struct.Struct('!BBBB')

def chunk_to_ipv4(chunk):
  if not isinstance(chunk, util.DataChunk):
    chunk = util.DataChunk(*chunk)
  length = len(chunk.data)
  if length <= 0:
    raise ValueError('length must be at least 1')
  elif length > 3:
    raise ValueError('cannot encode chunks longer than 3 bytes')
  elif chunk.offset % 3 != 0:
    raise ValueError('chunk offset must be multiples of 3')
  elif chunk.offset < 0:
    raise ValueError('chunk offset cannot be negative')
  elif chunk.offset // 3 >= 0x3f:
    raise ValueError('chunk offset cannot exceed {}'.format(0x3f))
  return '{}.{}.{}.{}'.format((length << 6) + (chunk.offset // 3),
                              chunk.data[0],
                              chunk.data[1] if length >= 2 else 255,
                              chunk.data[2] if length == 3 else 255)

def normalize_fqdn_suffix(fqdn_suffix):
  if not fqdn_suffix.endswith('.'):
    fqdn_suffix += '.'
  if fqdn_suffix.startswith('.'):
    fqdn_suffix = fqdn_suffix[1:]
  return fqdn_suffix


@enum.unique
class MessageType(enum.Enum):
  unknown = 0
  open_ticket = 1
  request_data = 2
  check_request = 3
  fetch_response = 4
  close_ticket = 5

  @staticmethod
  def deduce(version, variables, data):
    if version != '0':
      raise UnknownVersionError(version)
    keys = set(variables.keys())
    if 'retry' in keys:
      # ignore clearly optional variables
      keys.remove('retry')
    if keys == {'sz', 'rn', 'id'}:
      return MessageType.open_ticket
    elif keys == {'bf', 'wr', 'id'}:
      return MessageType.request_data
    elif keys == {'ck', 'id'}:
      return MessageType.check_request
    elif keys == {'ln', 'rd', 'id'}:
      return MessageType.fetch_response
    elif keys == {'ac', 'id'}:
      return MessageType.close_ticket
    return MessageType.unknown


class Message(collections.namedtuple('Message', ['version', 'type',
                                                 'variables', 'payload'])):
  @classmethod
  def create(cls, version, variables, payload):
    msgtype = MessageType.deduce(version, variables, payload)
    variables, payload = cls.normalize_data(msgtype, variables, payload)
    return cls(version, msgtype, variables, payload)

  @staticmethod
  def normalize_data(msgtype, variables, payload):
    newvars = {}
    for key in variables:
      if key in {'id', 'sz', 'rn', 'wr', 'ck', 'ln', 'rd', 'retry'}:
        newvars[key] = int(variables[key])
      elif key in {'bf'}:
        newvars[key] = binascii.unhexlify(variables[key])
      else:
        newvars[key] = variables[key]
    return newvars, payload

  @property
  def error(self):
    # Unfortunately, we currently don't have an easy way to find out whether
    # in a fetch_response payload. Simply wish the byte sequences 69 ## doesn't
    # appear in the payload.
    if len(self.payload.data) == 2 and self.payload.data.startswith(b'E'):
      return self.payload.data[1] or None
    return None

  def encode(self, fqdn_suffix=None):
    fqdn_suffix = normalize_fqdn_suffix(fqdn_suffix or DEFAULT_FQDN_SUFFIX)
    field_encoders = [
        ('retry', str),
        ('sz', '{:08d}'.format),
        ('rn', '{:08d}'.format),
        ('bf', lambda x: binascii.hexlify(x).decode('ascii')),
        ('wr', '{:08d}'.format),
        ('ck', '{:08d}'.format),
        ('ln', '{:08d}'.format),
        ('rd', '{:08d}'.format),
        ('ac', None),
        ('id', '{:08d}'.format),
    ]

    def encode_var(field, encoder):
      if encoder:
        return field + '-' + encoder(self.variables[field])
      return field

    variables = '.'.join(encode_var(field, encoder)
                         for field, encoder in field_encoders
                         if field in self.variables)
    return dnsrecord.DnsRecord(
        variables + '.v' + str(self.version) + '.' + fqdn_suffix,
        'IN', 'A', chunk_to_ipv4(self.payload))


class MessageParser:
  def __init__(self, fqdn_suffix=None):
    self._suffix = normalize_fqdn_suffix(fqdn_suffix or DEFAULT_FQDN_SUFFIX)
    self._re = regex.compile(
        r'''^\s*
              ((?P<flag>\w+)\.)*                # flags
              ((?P<var>\w+)-(?P<value>\w+)\.)+  # variables
              v(?P<version>\w+)\.               # version
              {!s}                              # suffix
            \s*$'''.format(regex.escape(self._suffix)),
        regex.VERSION1 | regex.VERBOSE)

  def parse(self, dns_record):
    m = self._re.fullmatch(dns_record.fqdn)
    if not m:
      raise ValueError(
          "fqdn '{}' is not in the expected format".format(dns_record.fqdn))
    variables = dict.fromkeys(m.captures('flag'), True)
    variables.update(zip(m.captures('var'), m.captures('value')))
    return Message.create(m.group('version'), variables,
                          ipv4_to_chunk(dns_record.value))
