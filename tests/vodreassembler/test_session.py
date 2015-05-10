import binascii
import unittest
from vodreassembler import dnsrecord
from vodreassembler import protocol
from vodreassembler import session
from vodreassembler import util


class TestSessionDatabase(unittest.TestCase):
  OPEN_TICKET_RECORD = dnsrecord.DnsRecord(
      'sz-00000061.rn-12345678.id-00000001.v0.tun.vpnoverdns.com.',
      'IN', 'A', '192.178.115.214')
  REQUEST_DATA_RECORDS = [
      dnsrecord.DnsRecord(
          'bf-f29074412b485b46b9f839f87f813474b2fef8e397ec63bf2aba103bed71',
          'IN', 'A', ''),
      dnsrecord.DnsRecord(
          'bf-0396ce4d54fd3ca5c629edc7785fde64d085a706cf84ec09551a130738b7',
          'IN', 'A', ''),
      dnsrecord.DnsRecord('bf-e0.wr-00000060.id-11695062.v0.tun.vpnoverdns.com.',
          'IN', 'A', '')
  ]
  REQUEST_DATA = (
      b'\xf2\x90tA+H[F\xb9\xf89\xf8\x7f\x814t\xb2\xfe\xf8\xe3\x97\xecc\xbf*'
      b'\xba\x10;\xedq\x03\x96\xceMT\xfd<\xa5\xc6)\xed\xc7x_\xded\xd0\x85'
      b'\xa7\x06\xcf\x84\xec\tU\x1a\x13\x078\xb7\xe0')

  def setUp(self):
    self._db = session.SessionDatabase()

  def test_build_from_records_open_ticket(self):
    self._db.build_from_records([self.OPEN_TICKET_RECORD])
    self.assertIn(0xb273d6, self._db)
    self.assertEquals(0xb273d6, self._db[0xb273d6].sess_id)
    self.assertFalse(self._db[0xb273d6].collision)
    self.assertEquals(12345678, self._db[0xb273d6].random_number)
    self.assertEquals(61, self._db[0xb273d6].request_length)
    self.assertEquals(1, len(self._db))

  def test_build_from_records_ignores_error(self):
    records = [dnsrecord.DnsRecord(self.OPEN_TICKET_RECORD.fqdn,
                                   self.OPEN_TICKET_RECORD.cls,
                                   self.OPEN_TICKET_RECORD.type,
                                   '128.69.10.255')]  # b'E\x10'
    self._db.build_from_records(records)
    self.assertNotIn(0xb273d6, self._db)
    self.assertEquals(0, len(self._db))

  def test_build_from_records_request_data(self):
    payload = util.DataChunk(b'E\x00', 0)  # E0 means no error (success)
    messages = [
        protocol.Message.create(
            '0',
            {'bf': binascii.hexlify(self.REQUEST_DATA[i:i+30]).decode('ascii'),
             'wr': i,'id': 12345678},
            payload)
        for i in range(0, len(self.REQUEST_DATA), 30)]
    records = [m.encode() for m in messages]
    self._db.build_from_records(records)
    self.assertIn(12345678, self._db)
    self.assertEquals(12345678, self._db[12345678].sess_id)
    self.assertFalse(self._db[12345678].collision)
    self.assertIsNone(self._db[12345678].random_number)
    self.assertEquals(len(self.REQUEST_DATA), self._db[12345678].request_length)
    self.assertEquals(self.REQUEST_DATA, self._db[12345678].request_data)


if __name__ == '__main__':
  unittest.main()
