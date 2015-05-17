========================
 vpnoverdns-reassembler
========================
vpnoverdns-reassembler is Python library and command line tools for analyzing DNS records from VPN-over-DNS service. Currently, only reassembling tickets (message exchanges) from records are supported.

Authors
=======
* Avi Prasad (aprasad6@illinois.edu)
* Eunsoo Roh (roh7@illinois.edu)

Requirements
============
* Python 3.4+ with pip
* `virtualenv <https://virtualenv.pypa.io/en/latest/>`_ (recommended)
* Unix-like operating system (recommended; only tested on Mac OS X)

Installation
============
1. Clone the repository e.g. ::

      git clone https://github.com/toukoaozaki/vpnoverdns-reassembler.git

2. Setup virtual environment with Python 3.4+ (optional). If you skip this step, you may need to adjust command line appropriately.

3. Run tests (optional) ::

      python setup.py test

4. Install package and dependencies ::

      python setup.py install

   For development, use the following command instead ::

      python setup.py develop

Command line interface
======================
Currently, one command line tool is supported to parse and save the tickets into a file. Type ::

  vodparse -h

for usage details.

For interactive inspection of the output from vodparse, you can do something like the following in the interpreter::

  import pickle
  from vodreassembler import socket
  database = pickle.load(open('path/to/file.db', 'rb'))
  print(database)
  # print all tickets
  for ticket in database:
    print(ticket)
  # Find all TcpSocket sessions present in the tickets
  sessions = socket.SocketSession.find_all(database)

Library
=======
Modules under vodreassembler/ are designed to be used as a library. Modules that might be the most useful include vodreassembler.ticket and vodreassembler.socket. Please refer to source code for public interfaces.

Caveats
=======
There are the following caveats we have discovered during the development.

1. Passive DNS dump as a data source does not retain any information on relative ordering, e.g. timestamps. This makes it almost impossible to handle when the same data source contains records with multiple different tickets having colliding identifiers.
2. When some records are missing, responses cannot be reconstructed due to zlib compression.
3. When some responses are missing in a particular TcpSocket session, it is almost impossible to recover HTTP payloads due to gzip (zlib) compression.
4. TcpSocket control messages also do not contain any information on relative ordering. This makes reassembly practically impossible when a single HTTP transaction is performed over multiple ticket exchanges, mostly due to computational complexity; there are :math:`n!` permutations to consider for reassembly of :math:`n` tickets, which is asmptotically worse than exponential time. For example, :math:`15!` is already :math:`1307674368000`, which is an awful lot cases to consider for just one session.
