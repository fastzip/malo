import pytest
import zlib
from malo.deflate.parse import Huff, Bitstream, DeflateReader, DeflateError

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

    bs = Bitstream(b"\xff")
    assert h.decode(bs) == 3 # "D"

    bs = Bitstream(b"\x03") # ....0 011
    assert h.decode(bs) == 2 # "C"
    assert h.decode(bs) == 1 # "B"

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

def test_deflate_backref_reaches_start():
    # dist == len(output): back-reference reaching position 0 is valid.
    # Fixed huffman block: literals 'a','b','c', back-ref(dist=3, len=3), EOB.
    data = b"\x4b\x4c\x4a\x06\x22\x00"
    assert zlib.decompress(data, -15) == b"abcabc"
    reader = DeflateReader("", data)
    assert reader.output == list(b"abcabc")

def test_deflate_backref_past_start():
    # dist > len(output): back-reference past the beginning should be rejected.
    # Same block as above but dist=4 instead of dist=3 (byte 4: 0x22 -> 0x62).
    data = b"\x4b\x4c\x4a\x06\x62\x00"
    with pytest.raises(AssertionError):
        DeflateReader("", data)

def test_deflate_big_stored_final():
    data = b"\x01\x05\x00\xfa\xff\x00\x01\x02\x03\x04"
    assert zlib.decompress(data, -15) == b"\x00\x01\x02\x03\x04"
    reader = DeflateReader("", data)
    assert reader.output == [0, 1, 2, 3, 4]

def test_deflate_btype11():
    # BFINAL=1, BTYPE=11 (reserved) — bottom 3 bits of first byte = 0b111 = 0x07
    with pytest.raises(DeflateError):
        DeflateReader("", b"\x07")

def test_deflate_stored_empty():
    # BFINAL=1, BTYPE=00, then 5 zero padding bits, LEN=0x0000, NLEN=0xFFFF
    data = b"\x01\x00\x00\xff\xff"
    assert zlib.decompress(data, -15) == b""
    reader = DeflateReader("", data)
    assert reader.output == []

def test_deflate_nonzero_padding_bits():
    # Same as stored empty but padding bit 3 is set — should be rejected.
    # deflate.py's ignore_rest_of_byte() raises DeflateError for non-zero padding.
    data = b"\x11\x00\x00\xff\xff"
    with pytest.raises(DeflateError):
        DeflateReader("", data)

def test_deflate_multiple_blocks():
    # Non-final compressed block followed by a final compressed block.
    # zlib.Z_SYNC_FLUSH emits a stored block flush between the two compress calls.
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    data = c.compress(b"hello") + c.flush(zlib.Z_SYNC_FLUSH) + c.compress(b"world") + c.flush()
    assert zlib.decompress(data, -15) == b"helloworld"
    reader = DeflateReader("", data)
    assert reader.output == list(b"helloworld")

def test_deflate_dist_extra_bits():
    # Back-reference with distance code 4 (dist=5, 1 extra bit).
    # All existing backref tests use dist≤4 (codes 0-2, zero extra bits).
    # Fixed huffman stream: literals "abcde" then backref(dist=5, len=3), EOB.
    data = b"\x4b\x4c\x4a\x4e\x49\x4d\x4c\x4a\x06\x00"
    assert zlib.decompress(data, -15) == b"abcdeabc"
    reader = DeflateReader("", data)
    assert reader.output == list(b"abcdeabc")

def test_deflate_overlap_dist2():
    # Overlapping back-reference: dist=2, len=6 expands "ab" → "abababab".
    # A naive snapshot-then-copy implementation copies only the 2 available bytes
    # instead of extending byte-by-byte; this test catches that bug.
    # Fixed huffman stream: literals "ab", backref(dist=2, len=6), EOB.
    data = b"\x4b\x4c\x4a\x04\x43\x00"
    assert zlib.decompress(data, -15) == b"abababab"
    reader = DeflateReader("", data)
    assert reader.output == list(b"abababab")

def test_deflate_sym286_287():
    # Symbols 286 and 287 have valid fixed-Huffman codes but are not valid
    # length/literal values; the decoder must reject them, not crash with IndexError.
    # Fixed block: BFINAL=1, BTYPE=01, then sym286 (code 0xC6, 8-bit).
    sym286 = b"\x1b\x03"
    sym287 = b"\x1b\x07"
    for data in (sym286, sym287):
        with pytest.raises(DeflateError):
            DeflateReader("", data)

def test_deflate_max_length():
    # Length code 285 encodes len=258 with *zero* extra bits, while the adjacent
    # code 284 encodes len=227-258 with *five* extra bits. Decoders that handle
    # the LEXT table off-by-one will misread the distance or subsequent data.
    # Fixed huffman: 'a' literal then backref(dist=1, len=258), EOB → 259 'a's.
    data = b"\x4b\x4c\x1c\xf1\x00\x00"
    assert zlib.decompress(data, -15) == b"a" * 259
    reader = DeflateReader("", data)
    assert reader.output == [ord("a")] * 259
