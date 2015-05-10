"""Module for session-related utilities."""

from vodreassembler import util
from vodreassembler import protocol


class Session:
  def __init__(self, sess_data):
    self._sess_data = sess_data

  @property
  def sess_id(self):
    return self._sess_data.id

  @property
  def collision(self):
    return self._sess_data.collision

  @property
  def random_number(self):
    return self._sess_data.rn

  @property
  def request_length(self):
    if (self._sess_data.request_length is None
        and self._sess_data.request_data is not None):
      return self._sess_data.request_data.length
    return self._sess_data.request_length

  @property
  def request_data(self):
    if self._sess_data.request_data is None:
      return
    return self._sess_data.request_data.getbytes()

  @property
  def response_length(self):
    if (self._sess_data.response_length is None
        and self._sess_data.response_data is not None):
      return self._sess_data.response_data.length
    return self._sess_data.response_length

  @property
  def response_data(self):
    if self._sess_data.response_data is None:
      return
    return self._sess_data.response_data.getbytes()


class _SessionData:
  def __init__(self, sess_id):
    self.id = sess_id
    self.collision = False
    self.rn = None
    self.request_length = None
    self.request_data = None
    self.response_length = None
    self.response_data = None

  def update(self, msg):
    assert msg.error is None
    if msg.type is protocol.MessageType.open_ticket:
      self._update_rn(msg.variables['rn'])
      self._update_request_length(msg.variables['sz'])
    elif msg.type is protocol.MessageType.request_data:
      self._update_request_data(msg.variables['bf'], msg.variables['wr'])
    elif msg.type is protocol.MessageType.check_request:
      # We don't really care about check_request at this point.
      pass
    elif msg.type is protocol.MessageType.fetch_response:
      self._update_response_data(msg.variables['ln'], msg.variables['rd'],
                                 msg.payload)
    elif msg.type is protocol.MessageType.close_ticket:
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
      if self.request_data.length is not None:
        self._update_request_length(self.request_data.length)
    except util.ChunkCollisionError:
      self.collision = True

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
      if segment_length < 48:
        self.response_data.length = segment_offset + segment_length
      if self.response_data.length is not None:
        self._update_response_length(self.response_data.length)
    except util.ChunkCollisionError:
      self.collision = True


class SessionDatabase:
  def __init__(self, fqdn_suffix=None):
    self._sessions = {}
    self._session_data = {}
    self._fqdn_suffix = fqdn_suffix

  def __getitem__(self, sess_id):
    return self._sessions[sess_id]

  def __contains__(self, sess_id):
    return sess_id in self._sessions

  def __len__(self):
    return len(self._sessions)

  def build_from_records(self, records):
    parser = protocol.MessageParser(self._fqdn_suffix)
    for r in records:
      try:
        msg = parser.parse(r)
      except ValueError:
        # Just ignore unparseable record.
        continue

      if msg.error:
        # ignore error
        continue

      if 'rn' in msg.variables:
        sess_id = int.from_bytes(msg.payload.data, byteorder='big')
      elif 'id' in msg.variables:
        sess_id = msg.variables['id']
      else:
        # Cannot map the record with any sessions; ignore
        continue

      session_data = self._get_or_create_session_data(sess_id)
      session_data.update(msg)

  def _get_or_create_session_data(self, sess_id):
    if sess_id not in self._sessions:
      data = _SessionData(sess_id)
      self._sessions[sess_id] = Session(data)
      self._session_data[sess_id] = data
    return self._session_data[sess_id]
