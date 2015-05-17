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
        uuid, msgtype, *other_params = ticket.request_message.split('\xa7')
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
