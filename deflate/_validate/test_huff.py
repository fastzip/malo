import zlib
from deflate import Huff, Bitstream, DeflateReader

def test_bitstream():
    bs = Bitstream(b"\x22\x01")
    assert bs.read_int(4) == 2
    assert bs.read_int(4) == 2
    assert bs.next() == 1
    assert bs.next() == 0

def test_single():
    bs = Bitstream(b"\x00")
    h = Huff([1, 1], 2)
    assert h.left == 0
    assert h.decode(bs) == 0

    bs = Bitstream(b"\xff")
    h = Huff([1, 1], 2)
    assert h.left == 0
    assert h.decode(bs) == 1


def test_incomplete():
    bs = Bitstream(b"\x00")
    h = Huff([1], 1)
    assert h.left > 0
    assert h.decode(bs) == 0

def test_example_from_rfc1951():
    bs = Bitstream(b"\x00")
    h = Huff([2, 1, 3, 3], 4)
    assert h.left == 0
    assert h.decode(bs) == 1 # "B"
    print()

    bs = Bitstream(b"\xff")
    assert h.decode(bs) == 3 # "D"
    print()

    bs = Bitstream(b"\x03") # ....0 011
    assert h.decode(bs) == 2 # "C"
    print()
    assert h.decode(bs) == 1 # "B"
    print()

def test_deflate_empty():
    data = zlib.compress(b"", -1, -15)
    reader = DeflateReader("", data)
    assert reader.output == []

def test_deflate_a():
    data = zlib.compress(b"a", -1, -15)
    reader = DeflateReader("", data)
    assert reader.output == [ord("a")]

def test_deflate_repeat():
    data = zlib.compress(b"\x01" * 100, -1, -15)
    reader = DeflateReader("", data)
    assert reader.output == [1] * 100

def test_deflate_big_stored_separate_final():
    data = b"\x00\x05\x00\xfa\xff\x00\x01\x02\x03\x04\x03\x00"
    assert zlib.decompress(data, -15) == b"\x00\x01\x02\x03\x04"
    reader = DeflateReader("", data)
    assert reader.output == [0, 1, 2, 3, 4]

def test_deflate_big_stored_final():
    data = b"\x01\x05\x00\xfa\xff\x00\x01\x02\x03\x04"
    assert zlib.decompress(data, -15) == b"\x00\x01\x02\x03\x04"
    reader = DeflateReader("", data)
    assert reader.output == [0, 1, 2, 3, 4]
