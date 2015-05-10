"""Miscellaneous utility functions and classes."""

import bitarray
import collections
import io
import types


class Error(Exception):
  pass


class IncompleteDataError(Error):
  pass


class UnexpectedChunkError(Error):
  pass


class ChunkPastEndError(UnexpectedChunkError):
  pass


class ChunkCollisionError(UnexpectedChunkError):
  pass


class DataChunk(collections.namedtuple('DataChunk', ['data', 'offset'])):
  pass


class DataAssembler:
  """Assembler for DataChunk objects.
  
  DataChunk represents a part of the entire data. DataAssembler can reconstruct
  the entire data by assembling multiple DataChunk objects into a single buffer.
  Each chunk is expected to be obtained by splitting the original data for every
  alignment bytes.
  """
  def __init__(self, alignment, storage=None, length=None):
    """Initialize DataAssembler for accepting chunks of given alignment.

    DataAssembler object takes ownership of provided storage object. Therefore,
    the storage should not be modified externally.

    Args:
      alignment (int): Alignment of each chunk. Offset of each chunk added must
        be divisible by this number. Also, every chunk but the last must have
        the same length as alignment.
      storage (optional): binary file object used as data storage for the
        assembler. Must support both read and write. If not provided, io.BytesIO
        is used.
      length (int, optional): Length of the entire data. Used to perform extra
        validations.
    """
    if not isinstance(alignment, int):
      raise TypeError("alignment "
                      "must be int".format(self.__init__.__name__))
    elif alignment <= 0:
      raise ValueError('alignment must be positive integer')
     
    if length is not None:
      if not isinstance(length, int):
        raise TypeError("{}: length "
                        "must be int or None".format(self.__init__.__name__))
      elif length < 0:
        raise ValueError("{}: length "
                         "cannot be negative".format(self.__init__.__name__))

    self._alignment = alignment
    bitarray_length = self._bitarray_length(length) if length is not None else 0
    self._has_chunk = bitarray.bitarray(bitarray_length)
    self._storage = storage or io.BytesIO(b'\x00' * (length or 0))
    self._length = length

    self._has_chunk.setall(False)

  def _bitarray_length(self, data_length):
    assert data_length is not None
    return 1 + (data_length - 1) // self._alignment

  @property
  def alignment(self):
    return self._alignment

  @property
  def complete(self):
    return self._has_chunk.all()

  @property
  def length(self):
    return self._length

  @length.setter
  def length(self, value):
    if self._length is None:
      if value is not None:
        self._length = value
        self._extend_bitmap(self._bitarray_length(value))
    elif value != self._length:
      raise ValueError('length cannot be changed once set')

  def getbytes(self, incomplete=False):
    if not incomplete and not self.complete:
      raise IncompleteDataError('cannot return incomplete data')

    curr = self._storage.seek(0)
    if curr != 0:
      raise RuntimeError('seek(0) failed')
    return self._storage.read()

  def add(self, data, offset):
    self._verify_chunk_params(data, offset)
    if self._data_already_added(data, offset):
      return
    self._update_bitmap(data, offset)
    self._write_data(data, offset)

  def _verify_chunk_params(self, data, offset):
    length = len(data)

    if offset < 0:
      raise ValueError('offset must be non-negative')
    elif self._length is not None and offset >= self._length:
      raise ChunkPastEndError('chunk at offset {} '
                              'is past the end of expected range')

    if offset % self._alignment != 0:
      raise ValueError('offset not aligned by {} bytes'.format(self._alignment))

    if length > self._alignment:
      raise ValueError('length of the chunk must not exceed the alignment')

    chunk_index = offset // self._alignment
    if self._is_last_chunk(chunk_index):
      if self._length is not None and offset + length != self._length:
        # This is the last chunk, which should fill the buffer without gap or
        # overflow.
        raise ValueError('incorrect length {} for the last chunk'.format(length))
    elif length != self._alignment:
        # Not the last chunk; data length must match alignment.
        raise ValueError('length of every chunk but the last '
                         'must match alignment.')

  def _is_last_chunk(self, chunk_index):
    return chunk_index >= len(self._has_chunk) - 1

  def _update_bitmap(self, data, offset):
    assert offset >= 0
    length = len(data)

    chunk_index = offset // self._alignment
    if chunk_index >= len(self._has_chunk):
      assert self._length is None
      # Extend the bitarray to ensure chunk_index is a valid index.
      self._extend_bitmap(chunk_index + 1)

    self._has_chunk[chunk_index] = True
    if self._length is None and length < self._alignment:
      # This must be the last chunk; now we know the length.
      self._length = offset + length

  def _extend_bitmap(self, length):
    assert length > len(self._has_chunk)
    extension = length - len(self._has_chunk)
    self._has_chunk.extend(False for i in range(extension))

  def _data_already_added(self, data, offset):
    # If we have seen the chunk before, check whether content matches.
    # It's an error they don't match.
    assert offset % self._alignment == 0
    chunk_index = offset // self._alignment
    try:
      if not self._has_chunk[chunk_index]:
        return False
    except IndexError:
      return False
    curr_data = self._read_data(offset, self._alignment)
    if data != curr_data:
      raise ChunkCollisionError('chunk at offset {} has been already added '
                                'with different content'.format(offset))
    return True

  def _read_data(self, offset, length):
    curr = self._storage.seek(offset)
    assert curr == offset
    return self._storage.read(length)

  def _write_data(self, data, offset):
    curr = self._storage.seek(offset)
    if curr < offset:
      # Seek to the offset failed somehow. Try padding to fill in the gap.
      self._storage.write(b'\x00' * (offset - curr))
    if self._storage.tell() != offset:
      raise RuntimeError('failed to seek to offset {}'.format(offset))
    assert self._storage.tell() == offset
    self._storage.write(data)

  def add_chunk(self, chunk):
    self.add(*chunk)
