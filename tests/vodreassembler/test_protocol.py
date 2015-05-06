import unittest
from vodreassembler import protocol


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


if __name__ == '__main__':
  unittest.main()
