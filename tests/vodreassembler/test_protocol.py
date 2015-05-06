import unittest
from vodreassembler import dnsrecord
from vodreassembler import protocol
from vodreassembler import util


class TestProtocol(unittest.TestCase):
  def test_ipv4_to_bytes(self):
    # 192 == 11000000, length 3 offset 0
    # 168 == 0xa8
    self.assertEquals(b'\xa8\x00\x00', protocol.ipv4_to_bytes('192.168.0.0'))
    # 129 == 10000001, length 2 offset 3, last octet ignored
    self.assertEquals(b'\x3f\x03', protocol.ipv4_to_bytes('129.63.3.8'))
    # 66 == 01000010, length 1 offset 6, last two octets ignored
    self.assertEquals(b'\x5b', protocol.ipv4_to_bytes('66.91.9.70'))
    # Test with invalid input
    with self.assertRaises(AttributeError):
      protocol.ipv4_to_bytes(None)
    with self.assertRaises(ValueError):
      protocol.ipv4_to_bytes('')
    with self.assertRaises(ValueError):
      protocol.ipv4_to_bytes('1.2.3')
    with self.assertRaises(ValueError):
      protocol.ipv4_to_bytes('1.2.3.4.5')
    with self.assertRaises(ValueError):
      protocol.ipv4_to_bytes('127.256.0.1')
    with self.assertRaises(ValueError):
      protocol.ipv4_to_bytes('-1.128.0.1')
    with self.assertRaises(ValueError):
      protocol.ipv4_to_bytes('1.128.300.1')
    with self.assertRaises(ValueError):
      protocol.ipv4_to_bytes('1.128.64.1999')

  def test_ipv4_to_chunk(self):
    # 192 == 11000000, length 3 offset 0
    # 168 == 0xa8
    self.assertEquals((b'\xa8\x00\x00', 0),
                      protocol.ipv4_to_chunk('192.168.0.0'))
    # 129 == 10000001, length 2 offset 3, last octet ignored
    self.assertEquals((b'\x3f\x03', 3), protocol.ipv4_to_chunk('129.63.3.8'))
    # 66 == 01000010, length 1 offset 6, last two octets ignored
    self.assertEquals((b'\x5b', 6), protocol.ipv4_to_chunk('66.91.9.70'))
    # Test with invalid input
    with self.assertRaises(AttributeError):
      protocol.ipv4_to_chunk(None)
    with self.assertRaises(ValueError):
      protocol.ipv4_to_chunk('')
    with self.assertRaises(ValueError):
      protocol.ipv4_to_chunk('1.2.3')
    with self.assertRaises(ValueError):
      protocol.ipv4_to_chunk('1.2.3.4.5')
    with self.assertRaises(ValueError):
      protocol.ipv4_to_chunk('127.256.0.1')
    with self.assertRaises(ValueError):
      protocol.ipv4_to_chunk('-1.128.0.1')
    with self.assertRaises(ValueError):
      protocol.ipv4_to_chunk('1.128.300.1')
    with self.assertRaises(ValueError):
      protocol.ipv4_to_chunk('1.128.64.1999')


class TestMessageParser(unittest.TestCase):
  DEFAULT_RECORD = dnsrecord.DnsRecord(
      'foo-12345678.bar-00000000.v0.tun.vpnoverdns.com.',
      'IN', 'A', '192.178.115.214')
  CUSTOM_RECORD = dnsrecord.DnsRecord(
      'foo-12345678.bar-00000000.v1.illinois.edu.',
      'IN', 'A', '192.178.115.214')
  VARIABLES = {'foo': '12345678', 'bar': '00000000'}
  DATA = util.DataChunk(b'\xb2\x73\xd6', 0)

  def test_default_suffix(self):
    parser = protocol.MessageParser()
    version, variables, data = parser.parse(self.DEFAULT_RECORD)
    self.assertEquals('0', version)
    self.assertEquals(self.VARIABLES, variables)
    self.assertEquals(self.DATA, data)

  def test_custom_suffix_nodot(self):
    parser = protocol.MessageParser(fqdn_suffix='illinois.edu')
    version, variables, data = parser.parse(self.CUSTOM_RECORD)
    self.assertEquals('1', version)
    self.assertEquals(self.VARIABLES, variables)
    self.assertEquals(self.DATA, data)

  def test_custom_suffix_begindot(self):
    parser = protocol.MessageParser(fqdn_suffix='.illinois.edu')
    version, variables, data = parser.parse(self.CUSTOM_RECORD)
    self.assertEquals('1', version)
    self.assertEquals(self.VARIABLES, variables)
    self.assertEquals(self.DATA, data)

  def test_custom_suffix_enddot(self):
    parser = protocol.MessageParser(fqdn_suffix='illinois.edu.')
    version, variables, data = parser.parse(self.CUSTOM_RECORD)
    self.assertEquals('1', version)
    self.assertEquals(self.VARIABLES, variables)
    self.assertEquals(self.DATA, data)

  def test_flags(self):
    parser = protocol.MessageParser()
    record = dnsrecord.DnsRecord('ac.' + self.DEFAULT_RECORD.fqdn,
                                 *self.DEFAULT_RECORD[1:])
    expected_vars = self.VARIABLES
    expected_vars['ac'] = True
    version, variables, data = parser.parse(record)
    self.assertEquals('0', version)
    self.assertEquals(expected_vars, variables)
    self.assertEquals(self.DATA, data)


if __name__ == '__main__':
  unittest.main()
