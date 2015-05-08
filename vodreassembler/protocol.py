"""VPN over DNS protocol utilities."""

import binascii
import collections
import enum
import regex
import struct
from vodreassembler import util

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
    for key in variables:
      if key in {'id', 'sz', 'rn', 'wr', 'ck', 'ln', 'rd', 'retry'}:
        variables[key] = int(variables[key])
      elif key in {'bf'}:
        variables[key] = binascii.unhexlify(variables[key])
    return variables, payload

  @property
  def error(self):
    if self.type is MessageType.fetch_response:
      return None
    if len(self.payload.data) == 2 and self.payload.data.startswith(b'E'):
      return self.payload.data[1]
    return None


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

