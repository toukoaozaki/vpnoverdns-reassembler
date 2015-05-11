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

  def test_chunk_to_ipv4(self):
    self.assertEquals('192.168.0.0',
                      protocol.chunk_to_ipv4((b'\xa8\x00\x00', 0)))
    self.assertEquals('129.63.3.255',
                      protocol.chunk_to_ipv4((b'\x3f\x03', 3)))
    self.assertEquals('66.91.255.255',
                      protocol.chunk_to_ipv4((b'\x5b', 6)))
    with self.assertRaises(ValueError):
      protocol.chunk_to_ipv4((b'', 0))
    with self.assertRaises(ValueError):
      protocol.chunk_to_ipv4((b'\x5b', -3))
    with self.assertRaises(ValueError):
      protocol.chunk_to_ipv4((b'\x5b', -1))
    with self.assertRaises(ValueError):
      protocol.chunk_to_ipv4((b'\x5b', 1))
    with self.assertRaises(ValueError):
      protocol.chunk_to_ipv4((b'\x5b\x5c\x5d\x5e', 0))


class TestQueryParser(unittest.TestCase):
  DEFAULT_RECORD = dnsrecord.DnsRecord(
      'foo-12345678.bar-00000000.v0.tun.vpnoverdns.com.',
      'IN', 'A', '192.178.115.214')
  CUSTOM_RECORD = dnsrecord.DnsRecord(
      'foo-12345678.bar-00000000.v0.illinois.edu.',
      'IN', 'A', '192.178.115.214')
  VARIABLES = {'foo': '12345678', 'bar': '00000000'}
  DATA = util.DataChunk(b'\xb2\x73\xd6', 0)

  def test_default_suffix(self):
    parser = protocol.QueryParser()
    query = parser.parse(self.DEFAULT_RECORD)
    self.assertEquals('0', query.version)
    self.assertEquals(self.VARIABLES, query.variables)
    self.assertEquals(self.DATA, query.payload)

  def test_custom_suffix_nodot(self):
    parser = protocol.QueryParser(fqdn_suffix='illinois.edu')
    query = parser.parse(self.CUSTOM_RECORD)
    self.assertEquals('0', query.version)
    self.assertEquals(self.VARIABLES, query.variables)
    self.assertEquals(self.DATA, query.payload)

  def test_custom_suffix_begindot(self):
    parser = protocol.QueryParser(fqdn_suffix='.illinois.edu')
    query = parser.parse(self.CUSTOM_RECORD)
    self.assertEquals('0', query.version)
    self.assertEquals(self.VARIABLES, query.variables)
    self.assertEquals(self.DATA, query.payload)

  def test_custom_suffix_enddot(self):
    parser = protocol.QueryParser(fqdn_suffix='illinois.edu.')
    query = parser.parse(self.CUSTOM_RECORD)
    self.assertEquals('0', query.version)
    self.assertEquals(self.VARIABLES, query.variables)
    self.assertEquals(self.DATA, query.payload)

  def test_flags(self):
    parser = protocol.QueryParser()
    record = dnsrecord.DnsRecord('ac.' + self.DEFAULT_RECORD.fqdn,
                                 *self.DEFAULT_RECORD[1:])
    expected_vars = self.VARIABLES
    expected_vars['ac'] = True
    query = parser.parse(record)
    self.assertEquals('0', query.version)
    self.assertEquals(expected_vars, query.variables)
    self.assertEquals(self.DATA, query.payload)


class TestQuery(unittest.TestCase):
  OPEN_TICKET_VARS = {'sz': '44', 'rn': '12345678', 'id': '00000001'}
  REQUEST_DATA_VARS = {'bf': 'abcdefabcdefabcdef', 'wr': '00000000',
                       'id': '98765432'}
  CHECK_REQUEST_VARS = {'ck': '00000020', 'id': '98765432'}
  FETCH_RESPONSE_VARS = {'ln': '00000048', 'rd': '00000000', 'id': '98765432'}
  CLOSE_TICKET_VARS = {'ac': True, 'id': '98765432'}

  OPEN_TICKET_VARS_RETRY = {'sz': '44', 'rn': '12345678', 'id': '00000001',
                            'retry': '1'}
  REQUEST_DATA_VARS_RETRY = {'bf': 'abcdefabcdefabcdef', 'wr': '00000000',
                             'id': '98765432', 'retry': '1'}
  CHECK_REQUEST_VARS_RETRY = {'ck': '00000020', 'id': '98765432', 'retry': '1'}
  FETCH_RESPONSE_VARS_RETRY = {'ln': '00000048', 'rd': '00000000',
                               'id': '98765432', 'retry': '1'}
  CLOSE_TICKET_VARS_RETRY = {'ac': True, 'id': '98765432', 'retry': '1'}

  def test_type_deduction_unknown_version(self):
    with self.assertRaises(protocol.UnknownVersionError):
      # Version 1 is not known to the implementation
      protocol.QueryType.deduce('1', self.OPEN_TICKET_VARS,
                                  util.DataChunk(b'\x00', 0))

  def test_type_deduction(self):
    querytype = protocol.QueryType.deduce('0', self.OPEN_TICKET_VARS,
                                          util.DataChunk(b'\x00\x00\x00', 0))
    self.assertEquals(protocol.QueryType.open_ticket, querytype)
    querytype = protocol.QueryType.deduce('0', self.REQUEST_DATA_VARS,
                                          util.DataChunk(b'\x00\x00\x00', 0))
    self.assertEquals(protocol.QueryType.request_data, querytype)
    querytype = protocol.QueryType.deduce('0', self.CHECK_REQUEST_VARS,
                                          util.DataChunk(b'\x00\x00\x00', 0))
    self.assertEquals(protocol.QueryType.check_request, querytype)
    querytype = protocol.QueryType.deduce('0', self.FETCH_RESPONSE_VARS,
                                          util.DataChunk(b'\x00\x00\x00', 0))
    self.assertEquals(protocol.QueryType.fetch_response, querytype)
    querytype = protocol.QueryType.deduce('0', self.CLOSE_TICKET_VARS,
                                          util.DataChunk(b'\x00\x00\x00', 0))
    self.assertEquals(protocol.QueryType.close_ticket, querytype)

  def test_type_deduction_retries(self):
    querytype = protocol.QueryType.deduce('0', self.OPEN_TICKET_VARS_RETRY,
                                          util.DataChunk(b'\x00\x00\x00', 0))
    self.assertEquals(protocol.QueryType.open_ticket, querytype)
    querytype = protocol.QueryType.deduce('0', self.REQUEST_DATA_VARS_RETRY,
                                          util.DataChunk(b'\x00\x00\x00', 0))
    self.assertEquals(protocol.QueryType.request_data, querytype)
    querytype = protocol.QueryType.deduce('0', self.CHECK_REQUEST_VARS_RETRY,
                                          util.DataChunk(b'\x00\x00\x00', 0))
    self.assertEquals(protocol.QueryType.check_request, querytype)
    querytype = protocol.QueryType.deduce('0', self.FETCH_RESPONSE_VARS_RETRY,
                                          util.DataChunk(b'\x00\x00\x00', 0))
    self.assertEquals(protocol.QueryType.fetch_response, querytype)
    querytype = protocol.QueryType.deduce('0', self.CLOSE_TICKET_VARS_RETRY,
                                          util.DataChunk(b'\x00\x00\x00', 0))
    self.assertEquals(protocol.QueryType.close_ticket, querytype)

  def test_normalize_data(self):
    variables, _ = protocol.Query.normalize_data(
        protocol.QueryType.open_ticket, self.OPEN_TICKET_VARS_RETRY,
        util.DataChunk(b'\x00\x00\x00', 0))
    for var, data in variables.items():
      self.assertIsInstance(data, int)
    variables, _ = protocol.Query.normalize_data(
        protocol.QueryType.open_ticket, self.REQUEST_DATA_VARS_RETRY,
        util.DataChunk(b'\x00\x00\x00', 0))
    for var, data in variables.items():
      if var == 'bf':
        self.assertEquals(b'\xab\xcd\xef\xab\xcd\xef\xab\xcd\xef', data)
      else:
        self.assertIsInstance(data, int)
    variables, _ = protocol.Query.normalize_data(
        protocol.QueryType.open_ticket, self.CHECK_REQUEST_VARS_RETRY,
        util.DataChunk(b'\x00\x00\x00', 0))
    for var, data in variables.items():
      self.assertIsInstance(data, int)
    variables, _ = protocol.Query.normalize_data(
        protocol.QueryType.open_ticket, self.FETCH_RESPONSE_VARS_RETRY,
        util.DataChunk(b'\x00\x00\x00', 0))
    for var, data in variables.items():
      self.assertIsInstance(data, int)
    variables, _ = protocol.Query.normalize_data(
        protocol.QueryType.open_ticket, self.CLOSE_TICKET_VARS_RETRY,
        util.DataChunk(b'\x00\x00\x00', 0))
    self.assertIsInstance(variables['retry'], int)
    self.assertIsInstance(variables['ac'], bool)  # unchanged
    self.assertIsInstance(variables['id'], int)

  def test_error(self):
    error_payload = util.DataChunk(b'E\x0a', 0)
    query = protocol.Query.create('0', self.OPEN_TICKET_VARS, error_payload)
    self.assertEquals(10, query.error)
    query = protocol.Query.create('0', self.REQUEST_DATA_VARS, error_payload)
    self.assertEquals(10, query.error)
    query = protocol.Query.create('0', self.CHECK_REQUEST_VARS, error_payload)
    self.assertEquals(10, query.error)
    query = protocol.Query.create('0', self.FETCH_RESPONSE_VARS, error_payload)
    self.assertEquals(10, query.error)
    query = protocol.Query.create('0', self.CLOSE_TICKET_VARS, error_payload)
    self.assertEquals(10, query.error)

  def test_encode(self):
    payload = util.DataChunk(b'\x00\x00\x00', 0)
    query = protocol.Query.create('0', self.OPEN_TICKET_VARS, payload)
    record = query.encode()
    self.assertEquals(
        'sz-00000044.rn-12345678.id-00000001.v0.tun.vpnoverdns.com.',
        record.fqdn)
    self.assertEquals(protocol.chunk_to_ipv4(payload), record.value)

    query = protocol.Query.create('0', self.REQUEST_DATA_VARS, payload)
    record = query.encode()
    self.assertEquals(
        'bf-abcdefabcdefabcdef.wr-00000000.id-98765432.v0.tun.vpnoverdns.com.',
        record.fqdn)
    self.assertEquals(protocol.chunk_to_ipv4(payload), record.value)

    query = protocol.Query.create('0', self.CHECK_REQUEST_VARS, payload)
    record = query.encode()
    self.assertEquals(
        'ck-00000020.id-98765432.v0.tun.vpnoverdns.com.',
        record.fqdn)
    self.assertEquals(protocol.chunk_to_ipv4(payload), record.value)

    query = protocol.Query.create('0', self.FETCH_RESPONSE_VARS, payload)
    record = query.encode()
    self.assertEquals(
        'ln-00000048.rd-00000000.id-98765432.v0.tun.vpnoverdns.com.',
        record.fqdn)
    self.assertEquals(protocol.chunk_to_ipv4(payload), record.value)

    query = protocol.Query.create('0', self.CLOSE_TICKET_VARS, payload)
    record = query.encode()
    self.assertEquals(
        'ac.id-98765432.v0.tun.vpnoverdns.com.',
        record.fqdn)
    self.assertEquals(protocol.chunk_to_ipv4(payload), record.value)


if __name__ == '__main__':
  unittest.main()
