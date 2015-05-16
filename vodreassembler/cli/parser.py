"""Command line tool for parsing vpnoverdata sources.

Currently, only conversion from DNS text dumps to ticket database is supported.
"""

import argparse
import collections
import pickle
from vodreassembler import dnsrecord, ticket

_SRC_TYPES = {
  'auto',
  'dns_dump',
}

_DEST_TYPES = {
  'auto',
  'ticket_db',
}

# Datapaths from one type to another. Key is a tuple defining a directed edge
# from one datatype to another, and value is the callable performing the
# conversion.
# Datatypes with double underscore (__) prefixes are internal in-memory
# representations.
_TRANSFORMERS = {
  ('dns_dump', '__dns_records') : 'parse_dns_dump',
  ('__dns_records', '__ticket_db') : 'generate_ticket_db',
  ('__ticket_db', 'ticket_db') : 'pickle_ticket_db',
}

def parse_args():
  parser = argparse.ArgumentParser(description='VPN-over-DNS data parser.')
  parser.add_argument('source', metavar='src', type=str,
                      help='Source file to be parsed.')
  parser.add_argument('dest', metavar='dest', type=str,
                      help='Destination file for the results.')
  parser.add_argument('--src_type', choices=['auto', 'dns_dump'],
                      type=str, default='auto',
                      help='Type of source data. Default is auto.')
  parser.add_argument('--dest_type', choices=['auto', 'ticket_db'],
                      type=str, default='auto',
                      help='Type of destination data. Default is auto.')
  return parser.parse_args()

def deduce_src_type(src_type):
  if src_type is not 'auto':
    return src_type
  # The only possible type is currently dns_dump
  return 'dns_dump'

def deduce_dest_type(dest_type):
  if dest_type is not 'auto':
    return dest_type
  # The only possible type is currently ticket_db
  return 'ticket_db'

def is_binary_type(data_type):
  if data_type == 'dns_dump':
    return False
  elif data_type == 'ticket_db':
    return True
  raise ValueError("Unknown or unsupported datatype: '{}'".format(data_type))

def parse_dns_dump(dns_dump):
  print('Loading DNS records from file...')
  return dnsrecord.from_dump(dns_dump)

def generate_ticket_db(dns_records):
  print('Generating ticket database from DNS records...')
  ticket_db = ticket.TicketDatabase()
  ticket_db.build_from_records(dns_records)
  return ticket_db

def pickle_ticket_db(ticket_db):
  print('Saving ticket database...')
  # TODO(toukoaozaki): try considering a different format.
  return pickle.dumps(ticket_db)

def compute_conversion_path(input_type, output_type):
  """Compute series of transformation for converting input to output."""
  adjacency_list = collections.defaultdict(list)
  for src, dest in _TRANSFORMERS.keys():
    adjacency_list[src].append(dest)
  # Use BFS to find the shortest path i.e. conversion with least steps.
  prev = {}
  queue = collections.deque((input_type,))

  while queue:
    node_type = queue.pop()
    for next_type in adjacency_list[node_type]:
      prev[next_type] = node_type
      if next_type == output_type:
        queue.clear()
        break
      queue.appendleft(next_type)

  if output_type not in prev:
    # TODO(toukoaozaki): More appropriate exceptions?
    raise Exception('no coversion path exists betweeen '
                    "types '{}' and '{}'".format(input_type, output_type))

  reverse_steps = []
  current_type = output_type
  while current_type != input_type:
    prev_type = prev.get(current_type, None)
    assert prev_type is not None
    edge = (prev_type, current_type)
    assert edge in _TRANSFORMERS
    transformer = _TRANSFORMERS[edge]
    if not callable(transformer):
      # Assume it is the name of the callable. The code is safe, because the
      # value of transformer is not user-provided.
      transformer = eval(transformer)

    reverse_steps.append(transformer)
    current_type = prev_type
  return reversed(reverse_steps)

def main():
  args = parse_args()
  src_type = deduce_src_type(args.src_type)
  dest_type = deduce_dest_type(args.dest_type)
  conversion_path = compute_conversion_path(src_type, dest_type)
  src_mode = 'rb' if is_binary_type(src_type) else 'rt'
  dest_mode = 'wb' if is_binary_type(dest_type) else 'wt'
  with open(args.source, mode=src_mode) as srcf:
    last_data = srcf
    # Apply series of steps
    for transform in conversion_path:
      last_data = transform(last_data)
    with open(args.dest, mode=dest_mode) as destf:
      destf.write(last_data)

if __name__ == '__main__':
  main()
