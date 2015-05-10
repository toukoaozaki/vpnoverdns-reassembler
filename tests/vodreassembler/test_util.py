import itertools
import os
import unittest
from vodreassembler import util


class TestDataAssembler(unittest.TestCase):
  def test_init_bad_args(self):
    with self.assertRaises(TypeError):
      util.DataAssembler(None)  # alignment must be int
    with self.assertRaises(TypeError):
      util.DataAssembler(1.1)  # alignment must be int
    with self.assertRaises(ValueError):
      util.DataAssembler(-1)  # alignment must be positive
    with self.assertRaises(ValueError):
      util.DataAssembler(0)  # alignment must be positive
    with self.assertRaises(TypeError):
      util.DataAssembler(1, length=1.1)  # size must be int or None
    with self.assertRaises(TypeError):
      util.DataAssembler(1, length='asdf')  # size must be int or None
    with self.assertRaises(ValueError):
      util.DataAssembler(1, length=-1)  # size must be non-negative

  def test_getbytes_incomplete(self):
    assembler = util.DataAssembler(2, length=5)
    with self.assertRaises(util.IncompleteDataError):
      assembler.getbytes()
    self.assertEquals(b'\x00\x00\x00\x00\x00',
                      assembler.getbytes(incomplete=True))
    assembler.add(b'\x01\x02', 2)
    with self.assertRaises(util.IncompleteDataError):
      assembler.getbytes()
    self.assertEquals(b'\x00\x00\x01\x02\x00',
                      assembler.getbytes(incomplete=True))

  def test_length_deduction(self):
    assembler = util.DataAssembler(3)
    self.assertIsNone(assembler.length)
    assembler.add(b'\xff\xfe', 0)
    self.assertEquals(2, assembler.length)
    self.assertEquals(b'\xff\xfe', assembler.getbytes())

    assembler = util.DataAssembler(3)
    self.assertIsNone(assembler.length)
    assembler.add(b'\xff\xfe\xfd', 0)
    self.assertIsNone(assembler.length)
    assembler.add(b'\x01\x02', 6)
    self.assertEquals(8, assembler.length)
    assembler.add(b'\xfc\xfb\x00', 3)
    self.assertEquals(b'\xff\xfe\xfd\xfc\xfb\x00\x01\x02', assembler.getbytes())

  def test_incorrect_sized_chunks(self):
    assembler = util.DataAssembler(3)
    with self.assertRaises(ValueError):
      assembler.add(b'\x00' * (assembler.alignment + 1), 0)
    assembler.add(b'\xff\xfe\xfd', 3)
    with self.assertRaises(ValueError):
      assembler.add(b'\x00' * (assembler.alignment + 1), 0)
    with self.assertRaises(util.UnexpectedChunkLengthError):
      assembler.add(b'\x00' * (assembler.alignment - 1), 0)
    with self.assertRaises(ValueError):
      assembler.add(b'\x00' * (assembler.alignment + 1), 6)
    self.assertEquals(b'\x00\x00\x00\xff\xfe\xfd',
                      assembler.getbytes(incomplete=True))
    # Test with predefined length
    assembler = util.DataAssembler(3, length=5)
    with self.assertRaises(ValueError):
      assembler.add(b'\x00\x00\x00\x00', 0)
    with self.assertRaises(ValueError):
      assembler.add(b'\x00\x00\x00\x00', 3)
    with self.assertRaises(util.UnexpectedChunkLengthError):
      assembler.add(b'\x00', 3)
    with self.assertRaises(util.UnexpectedChunkLengthError):
      assembler.add(b'\x00\x00\x00', 3)
    assembler.add(b'\xba\xbe', 3)
    self.assertEquals(b'\x00\x00\x00\xba\xbe',
                      assembler.getbytes(incomplete=True))
    assembler = util.DataAssembler(3, length=6)
    with self.assertRaises(util.UnexpectedChunkLengthError):
      assembler.add(b'\x00', 3)
    with self.assertRaises(util.UnexpectedChunkLengthError):
      assembler.add(b'\x00\x00', 3)
    assembler.add(b'\xfe\xba\xbe', 3)
    self.assertEquals(b'\x00\x00\x00\xfe\xba\xbe',
                      assembler.getbytes(incomplete=True))

  def test_collisions(self):
    assembler = util.DataAssembler(3)
    assembler.add(b'\x00\x01\x00', 3)
    with self.assertRaises(util.ChunkCollisionError):
      assembler.add(b'\x00\x02\x00', 3)
    assembler.add(b'\x00\x01\x00', 3)  # same content
    assembler.add(b'\x00\x03\x00', 0)
    with self.assertRaises(util.ChunkCollisionError):
      assembler.add(b'\x00\x04\x00', 0)
    assembler.add(b'\x00\x03\x00', 0)  # same content
    assembler.add(b'\x00\x05', 6)
    with self.assertRaises(util.ChunkCollisionError):
      assembler.add(b'\x00\x06', 6)
    with self.assertRaises(util.ChunkCollisionError):
      assembler.add(b'\x00', 6)
    with self.assertRaises(util.ChunkCollisionError):
      assembler.add(b'\x00\x00\x00', 6)
    # Collision with too long chunks should be handled as ValueError.
    # Note that the previous add has determined the length the whole data.
    with self.assertRaises(ValueError):
      assembler.add(b'\x00\x00\x00\x00', 6)
    assembler.add(b'\x00\x05', 6)  # same content
    self.assertEquals(b'\x00\x03\x00\x00\x01\x00\x00\x05',
                      assembler.getbytes())

  def test_maligned_offsets(self):
    assembler = util.DataAssembler(3)
    with self.assertRaises(ValueError):
      assembler.add(b'\x00\x00\x00', 1)
    with self.assertRaises(ValueError):
      assembler.add(b'\x00\x00\x00', 2)
    assembler.add(b'\xca\xfe\xba', 0)
    with self.assertRaises(ValueError):
      assembler.add(b'\x00\x00\x00', 4)
    with self.assertRaises(ValueError):
      assembler.add(b'\x00\x00\x00', 5)
    assembler.add(b'\xbe\x00\xff', 3)
    self.assertEquals(b'\xca\xfe\xba\xbe\x00\xff',
                      assembler.getbytes())

  def test_out_of_bound_offsets(self):
    assembler = util.DataAssembler(3)
    with self.assertRaises(ValueError):
      assembler.add(b'\x00\x00\x00', -1)
    assembler = util.DataAssembler(3, length=3)
    with self.assertRaises(ValueError):
      assembler.add(b'\x00\x00\x00', -1)
    with self.assertRaises(util.ChunkPastEndError):
      assembler.add(b'\x00\x00\x00', 3)
    assembler = util.DataAssembler(3, length=4)
    with self.assertRaises(ValueError):
      assembler.add(b'\x00\x00\x00', -1)
    with self.assertRaises(util.ChunkPastEndError):
      assembler.add(b'\x00\x00\x00', 6)

  def _generate_data(self, length, alignment):
    assert length > 0
    assert alignment > 0
    data = os.urandom(length)
    return data, [util.DataChunk(data[i:i+alignment], i)
                  for i in range(0, len(data), alignment)]

  def _test_sized_add(self, length, alignment):
    data, chunks = self._generate_data(length, alignment)
    # Test all possible permutations
    for sequence in itertools.permutations(chunks):
      assembler = util.DataAssembler(alignment, length=length)
      for chunk in sequence:
        assembler.add(chunk.data, chunk.offset)
      self.assertEquals(data, assembler.getbytes())
      # Same test with add_chunk()
      assembler = util.DataAssembler(alignment, length=length)
      for chunk in sequence:
        assembler.add_chunk(chunk)
      self.assertEquals(data, assembler.getbytes())

  def test_sized_add_3_1(self):
    self._test_sized_add(3, 1)

  def test_sized_add_9_2(self):
    self._test_sized_add(9, 2)

  def test_sized_add_9_3(self):
    self._test_sized_add(9, 3)

  def test_sized_add_10_3(self):
    self._test_sized_add(10, 3)

  def test_sized_add_11_3(self):
    self._test_sized_add(11, 3)

  def test_sized_add_11_4(self):
    self._test_sized_add(11, 4)

  def _test_unsized_add(self, length, alignment):
    data, chunks = self._generate_data(length, alignment)
    # Test all possible permutations
    for sequence in itertools.permutations(chunks):
      assembler = util.DataAssembler(alignment)
      for chunk in sequence:
        assembler.add(chunk.data, chunk.offset)
      self.assertEquals(data, assembler.getbytes())
      # Same test with add_chunk()
      assembler = util.DataAssembler(alignment)
      for chunk in sequence:
        assembler.add_chunk(chunk)
      self.assertEquals(data, assembler.getbytes())

  def test_unsized_add_3_1(self):
    self._test_unsized_add(3, 1)

  def test_unsized_add_9_2(self):
    self._test_unsized_add(9, 2)

  def test_unsized_add_9_3(self):
    self._test_unsized_add(9, 3)

  def test_unsized_add_10_3(self):
    self._test_unsized_add(10, 3)

  def test_unsized_add_11_3(self):
    self._test_unsized_add(11, 3)

  def test_unsized_add_11_4(self):
    self._test_unsized_add(11, 4)


if __name__ == '__main__':
  unittest.main()
