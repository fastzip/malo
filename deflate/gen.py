import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_src"))


def gen(filename: str, data: bytes) -> None:
    Path(filename).write_bytes(data)


def stored_block(data: bytes, final: bool = True) -> bytes:
    """Raw bytes for a deflate stored (non-compressed) block."""
    n = len(data)
    # First byte: bit0=BFINAL, bits1-2=BTYPE=00, bits3-7=padding (zero)
    return bytes([int(final)]) + struct.pack("<HH", n, n ^ 0xFFFF) + data


def compress_raw(data: bytes, level: int = 6, strategy: int = zlib.Z_DEFAULT_STRATEGY) -> bytes:
    c = zlib.compressobj(level=level, wbits=-15, strategy=strategy)
    return c.compress(data) + c.flush()


def compress_fixed(data: bytes) -> bytes:
    """Compress using fixed Huffman codes (Z_FIXED forces static code tables)."""
    return compress_raw(data, strategy=zlib.Z_FIXED)


# === accept/ ===

# accept/empty.deflate: stored block with no content → empty output
gen("accept/empty.deflate", stored_block(b""))

# accept/stored.deflate: single stored block
gen("accept/stored.deflate", stored_block(b"hello"))

# accept/stored_two_blocks.deflate: non-final stored block + final stored block
gen(
    "accept/stored_two_blocks.deflate",
    stored_block(b"hello", final=False) + stored_block(b" world"),
)

# accept/fixed_huffman.deflate: fixed Huffman codes (Z_FIXED strategy)
gen("accept/fixed_huffman.deflate", compress_fixed(b"hello"))

# accept/dynamic_huffman.deflate: dynamic Huffman with repetitive content
gen("accept/dynamic_huffman.deflate", compress_raw(b"hello world " * 50))

# accept/overlap_backref.deflate: overlapping back-reference (run-length encoding).
# dist=1, length>1: output extends from a position that overlaps the copy destination.
# Compressing 100 identical bytes produces: literal 'a', then back-ref len=99 dist=1.
gen("accept/overlap_backref.deflate", compress_raw(b"a" * 100, level=1))

# accept/long_backref.deflate: back-reference at maximum length (258).
# 300 identical bytes: literal 'a', back-ref len=258 dist=1, back-ref len=41 dist=1.
gen("accept/long_backref.deflate", compress_raw(b"a" * 300, level=9))

# accept/mixed.deflate: non-final stored block followed by a dynamic Huffman block
gen("accept/mixed.deflate", stored_block(b"hello ", final=False) + compress_raw(b"world"))


# === iffy/ ===

# iffy/nonzero_padding.deflate: stored block where the 5 padding bits between the
# 3-bit block header and the LEN field are non-zero.
# RFC 1951 says those bits are "ignored"; some decoders (e.g. this repo's deflate.py)
# assert they are zero. 0xF9 = 11111001b: BFINAL=1, BTYPE=00, padding bits = 11111.
_n = len(b"hello")
gen(
    "iffy/nonzero_padding.deflate",
    bytes([0xF9]) + struct.pack("<HH", _n, _n ^ 0xFFFF) + b"hello",
)


# === reject/ ===

# reject/reserved_btype.deflate: BTYPE=11 is reserved and must be rejected.
# First byte: BFINAL=1, BTYPE=11 → bits 0,1,2 = 1,1,1 → byte 0x07.
gen("reject/reserved_btype.deflate", bytes([0x07]))

# reject/nlen_mismatch.deflate: LEN=5 but NLEN=0x0000 (must be 5^0xFFFF = 0xFFFA)
gen(
    "reject/nlen_mismatch.deflate",
    bytes([0x01]) + struct.pack("<HH", 5, 0x0000) + b"hello",
)

# reject/truncated_stored.deflate: LEN=100 but only 5 bytes of data follow
gen(
    "reject/truncated_stored.deflate",
    bytes([0x01]) + struct.pack("<HH", 100, 100 ^ 0xFFFF) + b"short",
)

# reject/truncated_fixed.deflate: fixed Huffman stream cut 2 bytes short (no end-of-block)
_full = compress_fixed(b"hello world")
gen("reject/truncated_fixed.deflate", _full[:-2])

# reject/truncated_fixed_midcode.deflate: fixed Huffman stream cut after the first byte,
# in the middle of the literal code for b"A". This is a true mid-code truncation: the
# block header is present, but the decoder cannot finish reading the first symbol.
gen("reject/truncated_fixed_midcode.deflate", compress_fixed(b"A")[:1])

# reject/truncated_dynamic.deflate: dynamic Huffman stream cut 2 bytes short
_full = compress_raw(b"hello world " * 50)
gen("reject/truncated_dynamic.deflate", _full[:-2])

# reject/distance_before_start.deflate: fixed Huffman block where the very first symbol
# is a length-distance pair. Output is empty, so any distance is invalid.
#
# Bit layout (bits packed LSB-first per byte, Huffman codes sent MSB-first):
#   bit 0     BFINAL=1
#   bits 1-2  BTYPE=01 (fixed): bit1=1, bit2=0
#   bits 3-9  symbol 257 (length=3, 0 extra): 7-bit code 0b0000001 MSB-first = 0,0,0,0,0,0,1
#   bits 10-14 distance code 0 (dist=1, 0 extra): 5-bit code 0b00000 = 0,0,0,0,0
#
#   Byte 0: bits 0-7 = 1,1,0,0,0,0,0,0 = 0x03
#   Byte 1: bits 8-14 = 0,1,0,0,0,0,0  (bit9=1 from sym257 LSB; rest zero) = 0x02
gen("reject/distance_before_start.deflate", bytes([0x03, 0x02]))

# reject/bad_symbol.deflate: symbol 286 in a fixed Huffman block.
# Symbols 286-287 appear in the fixed code table (8-bit group 280-287) but are not
# valid literal/length values and must be rejected.
#
# Symbol 286 has 8-bit canonical code 0b11000110 (code value 198 = 192 + 6):
#   bit 0     BFINAL=1
#   bits 1-2  BTYPE=01 (fixed)
#   bits 3-10 symbol 286: 8-bit code 0b11000110 MSB-first = 1,1,0,0,0,1,1,0
#
#   Byte 0: bits 0-7 = 1,1,0,1,1,0,0,0 = 0x1B
#   Byte 1: bits 8-10 = 1,1,0 then padding = 0x03
gen("reject/bad_symbol.deflate", bytes([0x1B, 0x03]))

# reject/trailing_garbage.deflate: valid deflate stream with an extra byte appended.
# The stream ends cleanly after BFINAL=1; the trailing byte is not part of any block.
gen("reject/trailing_garbage.deflate", compress_raw(b"hello") + b"\x00")

# reject/non_final_flush.deflate: a single stored block where BFINAL=0.
# The block is internally valid (correct LEN/NLEN, data), but BFINAL=1 is never seen.
# RFC 1951: "BFINAL is set if and only if this is the last block of the data set."
# A stream with no final block is incomplete and must be rejected.
gen("reject/non_final_flush.deflate", stored_block(b"hello", final=False))

# === Dynamic Huffman tree invalidity cases ===
#
# Dynamic block header layout (bits packed LSB-first per byte):
#   bit 0:      BFINAL
#   bits 1-2:   BTYPE (10 = dynamic)
#   bits 3-7:   HLIT  (257 - 286 literal/length codes)
#   bits 8-12:  HDIST (1 - 32 distance codes)
#   bits 13-16: HCLEN (4 - 19 code-length codes)
#   then (HCLEN+4) × 3-bit CLEN values in order: 16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15
#
# For all three fixtures below:
#   BFINAL=1, BTYPE=10, HLIT=0 (257 codes), HDIST=0 (1 code), HCLEN=0 (4 CLEN codes)
#   Byte 0 = 0x05: bits 0-7 = 1,0,1,0,0,0,0,0 (BFINAL=1, BTYPE=10, HLIT=0)
#   Byte 1 = 0x00: bits 8-15 = 0,0,0,0,0,0,0,0 (HDIST=0, HCLEN bits 0-2 = 0)
#   Byte 2 bit 0 = 0: HCLEN bit 3 = 0  →  HCLEN = 0000 = 0  →  4 CLEN values to follow

# reject/dynamic_empty_clen.deflate: CLEN code lengths all zero — the code-length Huffman
# tree is empty (no symbols defined), so the literal/length/distance trees cannot be decoded.
#   Bytes 2-3: all zero → CLEN[16]=0, CLEN[17]=0, CLEN[18]=0, CLEN[0]=0
gen("reject/dynamic_empty_clen.deflate", bytes([0x05, 0x00, 0x00, 0x00]))

# reject/dynamic_oversubscribed_clen.deflate: four CLEN symbols each assigned code length 1.
# Sum = 4 × (1/2) = 2.0 > 1 → over-subscribed; bit patterns are multiply claimed.
#   Byte 2 = 0x92 (0b10010010):  bit0=0 (HCLEN[3]=0), bit1=1,bit2=0,bit3=0 (CLEN[16]=1),
#                                 bit4=1,bit5=0,bit6=0 (CLEN[17]=1), bit7=1 (CLEN[18][0]=1)
#   Byte 3 = 0x04 (0b00000100):  bit0=0,bit1=0 (CLEN[18][1:2]=0 → CLEN[18]=1),
#                                 bit2=1,bit3=0,bit4=0 (CLEN[0]=1)
gen("reject/dynamic_oversubscribed_clen.deflate", bytes([0x05, 0x00, 0x92, 0x04]))

# reject/dynamic_rle_no_prev.deflate: valid 2-symbol CLEN tree (symbol 0 → code 0,
# symbol 16 → code 1), but the very first code-length symbol is RLE-16 (copy-previous).
# RFC 1951: RLE-16 copies the previous code length; using it as the first symbol
# (when no previous exists) is invalid.
#   Byte 2 = 0x02 (0b00000010): HCLEN[3]=0, CLEN[16]=1 (bits 1-3), CLEN[17]=0, CLEN[18][0]=0
#   Byte 3 = 0x24 (0b00100100): CLEN[18][1:2]=0 (→CLEN[18]=0), CLEN[0]=1 (bits 2-4),
#                                 bit5=1 (code-length seq: symbol 16 → code "1"),
#                                 bits 6-7: RLE extra bits = 0,0 (count = 3)
gen("reject/dynamic_rle_no_prev.deflate", bytes([0x05, 0x00, 0x02, 0x24]))

# malicious/two_streams.deflate: two complete deflate streams concatenated.
# Each stream individually is valid (BFINAL=1, correct end-of-block).
# A strict single-stream decoder rejects the second stream as trailing garbage.
# A lenient streaming decoder (e.g. gzip multi-stream style) emits output from both.
# The ambiguity makes this adversarial: what data did you decompress?
import os as _os
_os.makedirs("malicious", exist_ok=True)
gen("malicious/two_streams.deflate", compress_raw(b"hello") + compress_raw(b"world"))
