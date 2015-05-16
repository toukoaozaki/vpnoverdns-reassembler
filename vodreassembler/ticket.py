"""Module for ticket-related utilities."""

from vodreassembler import util
from vodreassembler import protocol
import zlib


class Ticket:
  def __init__(self, ticket_data):
    self._ticket_data = ticket_data

  @property
  def ticket_id(self):
    return self._ticket_data.id

  @property
  def collision(self):
    return self._ticket_data.collision

  @property
  def random_number(self):
    return self._ticket_data.rn

  @property
  def request_length(self):
    if (self._ticket_data.request_length is None
        and self._ticket_data.request_data is not None):
      return self._ticket_data.request_data.length
    return self._ticket_data.request_length

  @property
  def request_data(self):
    if self._ticket_data.request_data is None:
      return None
    return self._ticket_data.request_data.getbytes()

  @property
  def raw_response_length(self):
    if (self._ticket_data.response_length is None
        and self._ticket_data.response_data is not None):
      return self._ticket_data.response_data.length
    return self._ticket_data.response_length

  @property
  def raw_response_data(self):
    if self._ticket_data.response_data is None:
      return None
    return self._ticket_data.response_data.getbytes()

  @property
  def response_data(self):
    try:
      data = self.raw_response_data
      if data:
        return zlib.decompress(data)

    except util.IncompleteDataError:
      pass
    return None

  @property
  def is_binary(self):
    try:
      # If the first byte of the request is zero, the messages exchanged are
      # both in utf-8 text. Otherwise, they must be binary.
      if self.request_data is not None:
        return self.request_data[0] != 0
    except util.IncompleteDataError:
      pass
    return None

  def __repr__(self):
    return ('Ticket(id={!r}, collision={!r}, '
            'request_length={!r}, '
            'raw_response_length={!r}, '
            'is_binary={!r})').format(self.ticket_id,
                                      self.collision,
                                      self.request_length,
                                      self.raw_response_length,
                                      self.is_binary)


class _TicketData:
  def __init__(self, ticket_id):
    self.id = ticket_id
    self.collision = False
    self.rn = None
    self.request_length = None
    self.request_data = None
    self.response_length = None
    self.response_data = None

  def update(self, query):
    assert query.error is None
    if query.type is protocol.QueryType.open_ticket:
      self._update_rn(query.variables['rn'])
      self._update_request_length(query.variables['sz'])
    elif query.type is protocol.QueryType.request_data:
      self._update_request_data(query.variables['bf'], query.variables['wr'])
    elif query.type is protocol.QueryType.check_request:
      if len(query.payload) == 4 and query.payload.startswith(b'L'):
        self._update_response_length(int.from_bytes(query.payload[1:],
                                                    byte_order='big'))
    elif query.type is protocol.QueryType.fetch_response:
      self._update_response_data(query.variables['ln'], query.variables['rd'],
                                 query.payload)
    elif query.type is protocol.QueryType.close_ticket:
      # We don't really care about close_ticket at this point.
      pass

  def _update_rn(self, rn):
    if self.rn is not None and self.rn != rn:
      self.collision = True
      return
    self.rn = rn

  def _update_request_length(self, length):
    if self.request_length is not None and self.request_length != length:
      self.collision = True
      return
    self.request_length = length

  def _update_request_data(self, data, offset):
    if self.request_data is None:
      self.request_data = util.DataAssembler(30, length=self.request_length)
    try:
      self.request_data.add(data, offset)
    except util.UnexpectedChunkError:
      self.collision = True
      return
    if self.request_data.length is not None:
      self._update_request_length(self.request_data.length)

  def _update_response_length(self, length):
    if self.response_length is not None and self.response_length != length:
      self.collision = True
      return
    self.response_length = length

  def _update_response_data(self, segment_length, segment_offset, chunk):
    if self.response_data is None:
      self.response_data = util.DataAssembler(3, length=self.response_length)
    # Response data is queried by split segments. chunk is a piece of data
    # within one of the segments. In order to reassemble the entire data, we
    # must first construct each segment from chunks, then assemble segments into
    # final data. Fortunately, the known implementation uses segment_length=48,
    # which is a multiple of 3; therefore a single DataAssembler can be used.
    absolute_offset = segment_offset + chunk.offset
    try:
      self.response_data.add(chunk.data, absolute_offset)
    except util.UnexpectedChunkError:
      self.collision = True
      return

    if segment_length < 48:
      try:
        self.response_data.length = segment_offset + segment_length
      except ValueError:
        self.collision = True
    if self.response_data.length is not None:
      self._update_response_length(self.response_data.length)


class TicketDatabase:
  def __init__(self, fqdn_suffix=None):
    self._tickets = {}
    self._ticket_data = {}
    self._fqdn_suffix = fqdn_suffix

  def __getitem__(self, ticket_id):
    return self._tickets[ticket_id]

  def __contains__(self, ticket_id):
    return ticket_id in self._tickets

  def __len__(self):
    return len(self._tickets)

  def __repr__(self):
    return '{' + ', '.join(map(repr, self)) + '}'

  def __iter__(self):
    # Use values, as keys are redundant.
    return iter(self._tickets.values())

  def build_from_records(self, records):
    parser = protocol.QueryParser(self._fqdn_suffix)
    for r in records:
      try:
        query = parser.parse(r)
      except ValueError:
        # Just ignore unparseable record.
        continue

      if query.error:
        # ignore error
        continue

      if 'rn' in query.variables:
        ticket_id = int.from_bytes(query.payload.data, byteorder='big')
      elif 'id' in query.variables:
        ticket_id = query.variables['id']
      else:
        # Cannot map the record with any tickets; ignore
        continue

      ticket_data = self._get_or_create_ticket_data(ticket_id)
      ticket_data.update(query)

  def _get_or_create_ticket_data(self, ticket_id):
    if ticket_id not in self._tickets:
      data = _TicketData(ticket_id)
      self._tickets[ticket_id] = Ticket(data)
      self._ticket_data[ticket_id] = data
    return self._ticket_data[ticket_id]
