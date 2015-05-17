import binascii
import os
import random
import struct
import unittest
from vodreassembler import dnsrecord
from vodreassembler import protocol
from vodreassembler import ticket
from vodreassembler import util
import zlib

def random_string(length):
  return ''.join(random.choice('abcdefghijklmnopqrstuvwxyz\xa7')
                 for _ in range(length))

def length_prefixed_utf8(text):
  result = text.encode('utf-8')
  return struct.pack('B', len(result)) + result


class TestTicketDatabase(unittest.TestCase):
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
  TEXT_REQUEST_MESSAGE = random_string(60)
  TEXT_REQUEST_DATA = None
  TEXT_REQUEST = b'\x00' + TEXT_REQUEST_MESSAGE.encode('utf-8')
  TEXT_RESPONSE_MESSAGE = random_string(100)
  TEXT_RESPONSE_DATA = None
  TEXT_RESPONSE = TEXT_RESPONSE_MESSAGE.encode('utf-8')
  BINARY_REQUEST_MESSAGE = 'foie gras'
  BINARY_REQUEST_DATA = os.urandom(51)
  BINARY_REQUEST = (length_prefixed_utf8(BINARY_REQUEST_MESSAGE)
                    + BINARY_REQUEST_DATA)
  BINARY_RESPONSE_MESSAGE = random_string(70)
  BINARY_RESPONSE_DATA = os.urandom(30)
  BINARY_RESPONSE = (length_prefixed_utf8(BINARY_RESPONSE_MESSAGE)
                     + BINARY_RESPONSE_DATA)
  COMPRESSED_TEXT_RESPONSE = zlib.compress(TEXT_RESPONSE)
  COMPRESSED_BINARY_RESPONSE = zlib.compress(BINARY_RESPONSE)

  def setUp(self):
    self._db = ticket.TicketDatabase()
    # use fixed seed for deterministic results
    self._random = random.Random(100)

  def test_build_from_records_open_ticket(self):
    self._db.build_from_records([self.OPEN_TICKET_RECORD])
    self.assertIn(0xb273d6, self._db)
    self.assertEqual(0xb273d6, self._db[0xb273d6].ticket_id)
    self.assertFalse(self._db[0xb273d6].collision)
    self.assertEqual(12345678, self._db[0xb273d6].random_number)
    self.assertEqual(61, self._db[0xb273d6].raw_request_length)
    self.assertEqual(1, len(self._db))

  def test_build_from_records_ignores_error(self):
    records = [dnsrecord.DnsRecord(self.OPEN_TICKET_RECORD.fqdn,
                                   self.OPEN_TICKET_RECORD.cls,
                                   self.OPEN_TICKET_RECORD.type,
                                   '128.69.10.255')]  # b'E\x10'
    self._random.shuffle(records)
    self._db.build_from_records(records)
    self.assertNotIn(0xb273d6, self._db)
    self.assertEqual(0, len(self._db))

  def test_build_from_records_text_request_data(self):
    payload = util.DataChunk(b'E\x00', 0)  # E0 means no error (success)
    queries = [
        protocol.Query.create(
            '0',
            {'bf': binascii.hexlify(self.TEXT_REQUEST[i:i+30]).decode('ascii'),
             'wr': i,'id': 12345678},
            payload)
        for i in range(0, len(self.TEXT_REQUEST), 30)]
    records = [q.encode() for q in queries]
    self._random.shuffle(records)
    self._db.build_from_records(records)
    self.assertIn(12345678, self._db)
    self.assertEqual(12345678, self._db[12345678].ticket_id)
    self.assertFalse(self._db[12345678].collision)
    self.assertIsNone(self._db[12345678].random_number)
    self.assertEqual(len(self.TEXT_REQUEST),
                     self._db[12345678].raw_request_length)
    self.assertEqual(self.TEXT_REQUEST, self._db[12345678].raw_request_data)
    self.assertEqual(self.TEXT_REQUEST_MESSAGE,
                     self._db[12345678].request_message)
    self.assertIsNone(self._db[12345678].request_data)

  def test_build_from_records_binary_request_data(self):
    payload = util.DataChunk(b'E\x00', 0)  # E0 means no error (success)
    queries = [
        protocol.Query.create(
            '0',
            {'bf': binascii.hexlify(
                self.BINARY_REQUEST[i:i+30]).decode('ascii'),
             'wr': i,'id': 12345678},
            payload)
        for i in range(0, len(self.BINARY_REQUEST), 30)]
    records = [q.encode() for q in queries]
    self._random.shuffle(records)
    self._db.build_from_records(records)
    self.assertIn(12345678, self._db)
    self.assertEqual(12345678, self._db[12345678].ticket_id)
    self.assertFalse(self._db[12345678].collision)
    self.assertIsNone(self._db[12345678].random_number)
    self.assertEqual(len(self.BINARY_REQUEST),
                     self._db[12345678].raw_request_length)
    self.assertEqual(self.BINARY_REQUEST, self._db[12345678].raw_request_data)
    self.assertEqual(self.BINARY_REQUEST_MESSAGE,
                     self._db[12345678].request_message)
    self.assertEqual(self.BINARY_REQUEST_DATA,
                     self._db[12345678].request_data)

  def test_build_from_records_text_response_data(self):
    compressed_length = len(self.COMPRESSED_TEXT_RESPONSE)
    response_segments = [self.COMPRESSED_TEXT_RESPONSE[i:i+48]
                         for i in range(0, compressed_length, 48)]
    records = []
    for i, segment in enumerate(response_segments):
      query_vars = {'ln': len(segment), 'rd': i*48, 'id': 12345678}
      for off in range(0, len(segment), 3):
        query = protocol.Query.create('0', query_vars,
                                      util.DataChunk(segment[off:off+3], off))
        records.append(query.encode())

    self._random.shuffle(records)
    self._db.build_from_records(records)
    self.assertIn(12345678, self._db)
    self.assertEqual(12345678, self._db[12345678].ticket_id)
    self.assertFalse(self._db[12345678].collision)
    self.assertIsNone(self._db[12345678].random_number)
    self.assertIsNone(self._db[12345678].raw_request_data)
    self.assertIsNone(self._db[12345678].raw_request_length)
    self.assertEqual(len(self.COMPRESSED_TEXT_RESPONSE),
                     self._db[12345678].raw_response_length)
    self.assertEqual(self.COMPRESSED_TEXT_RESPONSE,
                     self._db[12345678].raw_response_data)
    self.assertIsNone(self._db[12345678].response_data)
    self.assertEqual(self.TEXT_RESPONSE_MESSAGE,
                     self._db[12345678].response_message)

  def test_build_from_records_binary_response_data(self):
    compressed_length = len(self.COMPRESSED_BINARY_RESPONSE)
    response_segments = [self.COMPRESSED_BINARY_RESPONSE[i:i+48]
                         for i in range(0, compressed_length, 48)]
    records = []
    for i, segment in enumerate(response_segments):
      query_vars = {'ln': len(segment), 'rd': i*48, 'id': 12345678}
      for off in range(0, len(segment), 3):
        query = protocol.Query.create('0', query_vars,
                                      util.DataChunk(segment[off:off+3], off))
        records.append(query.encode())

    self._random.shuffle(records)
    self._db.build_from_records(records)
    self.assertIn(12345678, self._db)
    self.assertEqual(12345678, self._db[12345678].ticket_id)
    self.assertFalse(self._db[12345678].collision)
    self.assertIsNone(self._db[12345678].random_number)
    self.assertIsNone(self._db[12345678].raw_request_data)
    self.assertIsNone(self._db[12345678].raw_request_length)
    self.assertEqual(len(self.COMPRESSED_BINARY_RESPONSE),
                     self._db[12345678].raw_response_length)
    self.assertEqual(self.COMPRESSED_BINARY_RESPONSE,
                     self._db[12345678].raw_response_data)
    self.assertEqual(self.BINARY_RESPONSE_DATA,
                     self._db[12345678].response_data)
    self.assertEqual(self.BINARY_RESPONSE_MESSAGE,
                     self._db[12345678].response_message)


if __name__ == '__main__':
  unittest.main()
