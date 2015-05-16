"""Utilities for analyzing with VPN over DNS socket sessions."""

from vodreassembler import util


class SocketSession:
  def __init__(self, data):
    super().__init__()
    self._data = data

  @property
  def uuid(self):
    return self._data['uuid']

  @property
  def session_id(self):
    return self._data['id']

  @property
  def all_tickets(self):
    return self._data['tickets']

  @classmethod
  def find_all(cls, ticket_db):
    """Find all socket sessions from given ticket_db."""
    socket_db = {}
    for ticket in ticket_db:
      try:
        req_string, req_binary = _parse_request_data(ticket)
        uuid, msgtype, *other_params = req_string.split('\xa7')
        uuid = int(uuid)
        # TODO(toukoaozaki): support other message types
        if msgtype == 'SocketData':
          socket_id = int(other_params[0])
          key = (uuid, socket_id)
          if key not in socket_db:
            socket_db[key] = {'uuid': uuid, 'id': socket_id, 'tickets': []}
          socket_db[key]['tickets'].append(ticket)
      except (util.IncompleteDataError, ValueError):
        pass
    return tuple(cls(data) for data in socket_db.values())

  def __repr__(self):
    return ('SocketSession(uuid={!r}, '
            'session_id={!r}, '
            'num_tickets={!r})').format(self.uuid,
                                        self.session_id,
                                        len(self.all_tickets))


# Those utilities should be part of Ticket interface.
# TODO(toukoaozaki): refactor code into Ticket interface.
def _parse_request_data(ticket):
  data = ticket.request_data
  is_binary = ticket.is_binary
  if data is None:
    raise util.IncompleteDataError()
  string_length = data[0]
  assert (string_length != 0) == is_binary
  return data[1:string_length+1].decode('utf-8'), data[string_length+1:] or None

def _parse_response_data(data, is_binary):
  if data is None:
    raise util.IncompleteDataError()
  if is_binary:
    string_length = data[0]
    return data[1:string_length+1].decode('utf-8'), data[string_length+1:]
  return data.decode('utf-8'), None
