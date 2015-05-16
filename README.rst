========================
 vpnoverdns-reassembler
========================
vpnoverdns-reassembler is Python library and command line tools for analyzing DNS records from VPN-over-DNS service. Currently, only reassembling tickets (message exchanges) from records are supported.

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
