import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_src"))

from malo.zstd.construct import (
    ZSTD_MAGIC,
    ZstdBlockHeader,
    ZstdFrameHeader,
    ZstdSkippableFrame,
    compress,
    compress_with_prefix,
    simple_frame_header,
)


def gen(filename: str, data: bytes) -> None:
    Path(filename).write_bytes(data)


def raw_frame(content: bytes) -> bytes:
    """Minimal valid zstd frame using an uncompressed (Raw_Block) block.
    Useful for fixtures where we care about frame structure, not compression."""
    fh = simple_frame_header(len(content)).pack()
    bh = ZstdBlockHeader(last_block=True, block_type=0, block_size=len(content)).pack()
    return fh + bh + content


# accept/simple.zst: produced by libzstd via C API
gen("accept/simple.zst", compress(b"hello"))

# accept/empty.zst
gen("accept/empty.zst", compress(b""))

# accept/raw_block.zst: manually constructed; no entropy coding
gen("accept/raw_block.zst", raw_frame(b"hello"))

# accept/multi_frame.zst: two concatenated frames — valid per spec
gen("accept/multi_frame.zst", compress(b"hello") + compress(b" world"))

# accept/skippable_prefix.zst: skippable frame before a real frame
gen(
    "accept/skippable_prefix.zst",
    ZstdSkippableFrame(data=b"user metadata").pack() + compress(b"hello"),
)

# iffy/skippable_only.zst: skippable frame with nothing following
gen("iffy/skippable_only.zst", ZstdSkippableFrame(data=b"no data frame follows").pack())

# reject/truncated_skippable*.zst: skippable frame truncated at four distinct positions
# Structure: magic(4) + frame_size(4) + body(N)
_sf = ZstdSkippableFrame(data=b"hello world").pack()  # 4+4+11=19 bytes
gen("reject/truncated_skippable_no_size.zst", _sf[:4])   # only magic, size field missing entirely
gen("reject/truncated_skippable_mid_size.zst", _sf[:6])  # magic + 2 of 4 size bytes
gen("reject/truncated_skippable_no_body.zst", _sf[:8])   # magic + full size field, body absent
gen("reject/truncated_skippable.zst", _sf[:11])          # magic + size + 3 of 11 body bytes

# accept/skippable_magic_max.zst: skippable frame using the highest valid magic (0x184D2A5F)
gen(
    "accept/skippable_magic_max.zst",
    ZstdSkippableFrame(magic=0x184D2A5F, data=b"hi").pack() + compress(b"hello"),
)

# iffy/empty_skippable.zst: zero-size skippable frame (body absent, frame_size=0)
gen(
    "iffy/empty_skippable.zst",
    ZstdSkippableFrame(data=b"").pack() + compress(b"hello"),
)

# iffy/skippable_between_frames.zst: skippable frame sandwiched between two data frames.
# Tests that decoders permit skippable frames anywhere in the stream, not just as a prefix.
gen(
    "iffy/skippable_between_frames.zst",
    compress(b"hello")
    + ZstdSkippableFrame(data=b"inter-frame marker").pack()
    + compress(b" world"),
)

# iffy/consecutive_skippable_frames.zst: three skippable frames back-to-back between two
# real frames.  Tests that decoders loop over skippable frames rather than expecting at
# most one before the next data frame.
gen(
    "iffy/consecutive_skippable_frames.zst",
    compress(b"hello")
    + ZstdSkippableFrame(data=b"first").pack()
    + ZstdSkippableFrame(data=b"second").pack()
    + ZstdSkippableFrame(data=b"third").pack()
    + compress(b" world"),
)

# iffy/consecutive_zero_byte_frames.zst: three zero-byte data frames followed by a real
# frame.  Each empty frame is a valid independently-decodable zstd frame with 0 bytes of
# content.  Tests that decoders accept zero-byte frames anywhere in a multi-frame stream.
_empty_frame = (
    simple_frame_header(0).pack()
    + ZstdBlockHeader(last_block=True, block_type=0, block_size=0).pack()
)
gen(
    "iffy/consecutive_zero_byte_frames.zst",
    _empty_frame + _empty_frame + _empty_frame + compress(b"hello"),
)

# malicious/declared_size_plus_one.zst: header claims 6 bytes, actual decompressed content is 5
# malicious/declared_size_minus_one.zst: header claims 4 bytes, actual decompressed content is 5
_content = b"hello"
_bh = ZstdBlockHeader(last_block=True, block_type=0, block_size=len(_content)).pack()
for _name, _declared in [("plus_one", len(_content) + 1), ("minus_one", len(_content) - 1)]:
    gen(
        f"malicious/declared_size_{_name}.zst",
        ZstdFrameHeader(
            fhd=0xE0,  # Single_Segment=1, FCS_Flag=3 (8-byte CS), no checksum
            content_size=struct.pack("<Q", _declared),
        ).pack()
        + _bh
        + _content,
    )

# reject/bad_magic.zst: magic off by one
_valid = compress(b"hello")
gen("reject/bad_magic.zst", struct.pack("<I", ZSTD_MAGIC ^ 0x01) + _valid[4:])

# reject/reserved_bit_set.zst: FHD bit 3 (Reserved_Bit) set — spec says must be zero
gen(
    "reject/reserved_bit_set.zst",
    ZstdFrameHeader(
        fhd=0xE8,  # 0b11101000: FCS_Flag=3, Single_Segment=1, Reserved_Bit=1
        content_size=struct.pack("<Q", 5),
    ).pack()
    + ZstdBlockHeader(last_block=True, block_type=0, block_size=5).pack()
    + b"hello",
)

# reject/reserved_block_type.zst: block type 3 is reserved
gen(
    "reject/reserved_block_type.zst",
    simple_frame_header(5).pack()
    + ZstdBlockHeader(last_block=True, block_type=3, block_size=5).pack()
    + b"hello",
)

# reject/truncated.zst: block header declares 100 bytes, stream ends after 5
gen(
    "reject/truncated.zst",
    simple_frame_header(100).pack()
    + ZstdBlockHeader(last_block=True, block_type=0, block_size=100).pack()
    + b"short",
)

# reject/no_final_block.zst: block with Last_Block=0, stream ends — frame never terminated
gen(
    "reject/no_final_block.zst",
    simple_frame_header(5).pack()
    + ZstdBlockHeader(last_block=False, block_type=0, block_size=5).pack()
    + b"hello",
)

# reject/junk_after_frame.zst: valid frame followed by one byte that starts no valid frame
gen("reject/junk_after_frame.zst", compress(b"hello") + b"\xff")

# reject/bare_block.zst: block header + body with no frame header (no magic, no FHD)
gen(
    "reject/bare_block.zst",
    ZstdBlockHeader(last_block=True, block_type=0, block_size=5).pack()
    + b"hello",
)

# reject/bare_block_then_frame.zst: bare block followed by a valid frame.
# The leading bytes don't match any frame magic, so the whole stream is invalid.
gen(
    "reject/bare_block_then_frame.zst",
    ZstdBlockHeader(last_block=True, block_type=0, block_size=5).pack()
    + b"hello"
    + compress(b"hello"),
)

# reject/truncated_rle.zst: RLE_Block header declares 5 bytes but the body byte is missing
gen(
    "reject/truncated_rle.zst",
    simple_frame_header(5).pack()
    + ZstdBlockHeader(last_block=True, block_type=1, block_size=5).pack(),
    # RLE body (1 byte) absent
)

# reject/truncated_compressed.zst: a real compressed block (not raw) cut 5 bytes short.
# Repetitive content guarantees libzstd emits a Compressed_Block rather than a Raw_Block.
_full = compress(b"aaa" * 200)
gen("reject/truncated_compressed.zst", _full[:-5])
gen("reject/truncated_compressed1.zst", _full[:-1])

# malicious/block_exceeds_frame_size.zst: block_size=100 but frame declares content_size=5.
# The block contains more data than the frame header promises.
gen(
    "malicious/block_exceeds_frame_size.zst",
    simple_frame_header(5).pack()
    + ZstdBlockHeader(last_block=True, block_type=0, block_size=100).pack()
    + b"a" * 100,
)

# reject/bad_checksum.zst: Content_Checksum_Flag set, checksum present but wrong value
_content = b"hello"
gen(
    "reject/bad_checksum.zst",
    simple_frame_header(len(_content), checksum=True).pack()
    + ZstdBlockHeader(last_block=True, block_type=0, block_size=len(_content)).pack()
    + _content
    + b"\x00\x00\x00\x00",  # wrong: correct value is lower 32 bits of xxHash64(_content)
)

# reject/missing_checksum.zst: Content_Checksum_Flag set in FHD but no checksum appended
gen(
    "reject/missing_checksum.zst",
    simple_frame_header(len(_content), checksum=True).pack()
    + ZstdBlockHeader(last_block=True, block_type=0, block_size=len(_content)).pack()
    + _content,
)

# reject/truncated_checksum.zst: Content_Checksum_Flag set in FHD but partial checksum
gen(
    "reject/missing_checksum.zst",
    simple_frame_header(len(_content), checksum=True).pack()
    + ZstdBlockHeader(last_block=True, block_type=0, block_size=len(_content)).pack()
    + _content
    + b"\x00\x00",
)

# iffy/empty_with_checksum.zst: empty frame (0-byte content) with Content_Checksum enabled.
# The correct checksum is the lower 32 bits of xxHash64(b"") = 0x51D8E999 (LE: 99 e9 d8 51).
gen(
    "iffy/empty_with_checksum.zst",
    simple_frame_header(0, checksum=True).pack()
    + ZstdBlockHeader(last_block=True, block_type=0, block_size=0).pack()
    + b"\x99\xe9\xd8\x51",  # xxHash64(b"") lower 32 bits, little-endian
)

# reject/empty_invalid_checksum.zst: same structure as empty_with_checksum but checksum is wrong.
gen(
    "reject/empty_invalid_checksum.zst",
    simple_frame_header(0, checksum=True).pack()
    + ZstdBlockHeader(last_block=True, block_type=0, block_size=0).pack()
    + b"\x00\x00\x00\x00",  # wrong: correct value is 0x51D8E999
)

# --- RLE_Block (block_type=1): body is one byte, decompressed output is that byte * block_size ---

# accept/rle_block.zst: normal use — 1 byte expands to 5
gen(
    "accept/rle_block.zst",
    simple_frame_header(5).pack()
    + ZstdBlockHeader(last_block=True, block_type=1, block_size=5).pack()
    + b"a",
)

# accept/rle_block_len1.zst: block_size=1 — negative compression ratio
# (3-byte header + 1-byte body = 4 bytes in → 1 byte out)
gen(
    "accept/rle_block_len1.zst",
    simple_frame_header(1).pack()
    + ZstdBlockHeader(last_block=True, block_type=1, block_size=1).pack()
    + b"x",
)

# iffy/raw_block_empty.zst: Raw_Block with block_size=0 — no body bytes.
# The spec prohibits block_size > Block_Maximum_Size but does not forbid 0.
gen(
    "iffy/raw_block_empty.zst",
    simple_frame_header(0).pack()
    + ZstdBlockHeader(last_block=True, block_type=0, block_size=0).pack(),
)

# iffy/rle_block_empty.zst: RLE_Block with block_size=0 (Regenerated_Size=0).
# Per spec the body is always exactly 1 byte regardless of block_size, so the
# body byte is present but produces no output.
gen(
    "iffy/rle_block_empty.zst",
    simple_frame_header(0).pack()
    + ZstdBlockHeader(last_block=True, block_type=1, block_size=0).pack()
    + b"\x00",
)

# iffy/multi_empty_blocks.zst: three non-final empty raw blocks followed by a final content block.
# Exercises the block-loop path in parsers more than a single empty block does.
gen(
    "iffy/multi_empty_blocks.zst",
    simple_frame_header(5).pack()
    + ZstdBlockHeader(last_block=False, block_type=0, block_size=0).pack()
    + ZstdBlockHeader(last_block=False, block_type=0, block_size=0).pack()
    + ZstdBlockHeader(last_block=False, block_type=0, block_size=0).pack()
    + ZstdBlockHeader(last_block=True, block_type=0, block_size=5).pack()
    + b"hello",
)

# --- FCS_Flag variants ---

# accept/fcs_2byte.zst: FCS_Flag=1 — content size as 2-byte LE
# FHD=0x60: bits[7:6]=01 (FCS_Flag=1), bit[5]=1 (Single_Segment), rest=0
# NOTE: With FCS_Flag=1 the decoder adds 256 to the stored value, so stored=5 → declared=261.
# Content is only 5 bytes, making this a declared-size mismatch (261 declared, 5 actual).
gen(
    "malicious/fcs_2byte_wrong_offset.zst",
    ZstdFrameHeader(fhd=0x60, content_size=struct.pack("<H", 5)).pack()
    + ZstdBlockHeader(last_block=True, block_type=0, block_size=5).pack()
    + b"hello",
)

# accept/fcs_2byte_offset.zst: FCS_Flag=1 used correctly with the +256 offset.
# Stored value=0 → declared content_size = 0+256 = 256. Content is exactly 256 bytes.
gen(
    "accept/fcs_2byte_offset.zst",
    ZstdFrameHeader(fhd=0x60, content_size=struct.pack("<H", 0)).pack()
    + ZstdBlockHeader(last_block=True, block_type=0, block_size=256).pack()
    + b"a" * 256,
)

# accept/fcs_4byte.zst: FCS_Flag=2 — content size as 4-byte LE
# FHD=0xA0: bits[7:6]=10 (FCS_Flag=2), bit[5]=1 (Single_Segment), rest=0
gen(
    "accept/fcs_4byte.zst",
    ZstdFrameHeader(fhd=0xA0, content_size=struct.pack("<I", 5)).pack()
    + ZstdBlockHeader(last_block=True, block_type=0, block_size=5).pack()
    + b"hello",
)

# accept/fcs_1byte.zst: FCS_Flag=0 with Single_Segment=1 — content size as 1-byte LE.
# FHD=0x20: bits[7:6]=00 (FCS_Flag=0), bit[5]=1 (Single_Segment → 1-byte FCS present, no offset).
# This is the only FCS variant without an offset; value 5 directly encodes content_size=5.
gen(
    "accept/fcs_1byte.zst",
    ZstdFrameHeader(fhd=0x20, content_size=struct.pack("<B", 5)).pack()
    + ZstdBlockHeader(last_block=True, block_type=0, block_size=5).pack()
    + b"hello",
)

# accept/no_content_size.zst: FCS_Flag=0 with Single_Segment=0 — no size declared at all.
# Window_Descriptor=0x00 encodes the minimum window size: (1+0/8)*2^(10+0) = 1 KB.
# FHD=0x00: bits[7:6]=00 (FCS_Flag=0), bit[5]=0 (not single-segment → Window_Descriptor present)
gen(
    "accept/no_content_size.zst",
    ZstdFrameHeader(fhd=0x00, window_descriptor=0x00).pack()
    + ZstdBlockHeader(last_block=True, block_type=0, block_size=5).pack()
    + b"hello",
)

# accept/multi_block.zst: two raw blocks in a single frame
_c1, _c2 = b"hello", b" world"
gen(
    "accept/multi_block.zst",
    simple_frame_header(len(_c1) + len(_c2)).pack()
    + ZstdBlockHeader(last_block=False, block_type=0, block_size=len(_c1)).pack()
    + _c1
    + ZstdBlockHeader(last_block=True, block_type=0, block_size=len(_c2)).pack()
    + _c2,
)

# --- Unused_Bit (FHD bit 4): "should be 0" per spec, not "must" ---

# iffy/unused_bit_set.zst
# FHD=0xF0: bits[7:6]=11 (FCS_Flag=3), bit[5]=1 (Single_Segment), bit[4]=1 (Unused_Bit)
gen(
    "iffy/unused_bit_set.zst",
    ZstdFrameHeader(fhd=0xF0, content_size=struct.pack("<Q", 5)).pack()
    + ZstdBlockHeader(last_block=True, block_type=0, block_size=5).pack()
    + b"hello",
)

# iffy/single_segment_16mb.zst: Single_Segment=1 forces decoder to pre-allocate a contiguous
# 16 MB output buffer before any data is read. Uses 128 × 128 KB RLE blocks, so the file
# is ~525 bytes but decompresses to 16 MB.
_16mb = 16 * 1024 * 1024
_chunk = 128 * 1024  # max recommended block size per spec
_rle_blocks = bytearray()
_remaining = _16mb
while _remaining > 0:
    _sz = min(_remaining, _chunk)
    _remaining -= _sz
    _rle_blocks += ZstdBlockHeader(last_block=(_remaining == 0), block_type=1, block_size=_sz).pack()
    _rle_blocks += b"\x00"
gen(
    "iffy/single_segment_16mb.zst",
    simple_frame_header(_16mb).pack() + bytes(_rle_blocks),
)

# iffy/single_segment_1gb.zst: Single_Segment=1 with FCS = 1 GB (Window_Size = 1 GB).
# Mirrors window_1gb.zst but exercises the SSF path. Uses 8192 × 128 KB RLE blocks;
# the file is ~32 KB but decompresses to 1 GB.
_1gb = 1024 * 1024 * 1024
_rle_blocks_1gb = bytearray()
_remaining = _1gb
while _remaining > 0:
    _sz = min(_remaining, _chunk)
    _remaining -= _sz
    _rle_blocks_1gb += ZstdBlockHeader(last_block=(_remaining == 0), block_type=1, block_size=_sz).pack()
    _rle_blocks_1gb += b"\x00"
gen(
    "iffy/single_segment_1gb.zst",
    simple_frame_header(_1gb).pack() + bytes(_rle_blocks_1gb),
)

# --- Dict_ID_Flag variants ---

# accept/dict_id_zero.zst: Dict_ID_Flag=1 (1-byte field present) with value=0.
# RFC 8878: dict_id=0 means "no dictionary" — valid encoding, semantically equivalent to no dict field.
# FHD=0xE1: FCS_Flag=3, Single_Segment=1, Dict_ID_Flag=1
gen(
    "accept/dict_id_zero.zst",
    ZstdFrameHeader(fhd=0xE1, content_size=struct.pack("<Q", 5), dict_id=b"\x00").pack()
    + ZstdBlockHeader(last_block=True, block_type=0, block_size=5).pack()
    + b"hello",
)

# iffy/dict_id_{1,2,4}byte.zst: all three non-zero dict ID field widths.
# Content is a raw block that doesn't use the dict; decoders without it "should" reject per spec.
# FHD Dict_ID_Flag encoding: 01=1-byte, 10=2-byte, 11=4-byte (bits 1:0 of FHD)
for _fhd, _dict_id in [
    (0xE1, b"\x42"),                     # 1-byte:  ID=66
    (0xE2, struct.pack("<H", 0x1234)),   # 2-byte:  ID=4660
    (0xE3, struct.pack("<I", 12345)),    # 4-byte:  ID=12345
]:
    _nbytes = len(_dict_id)
    gen(
        f"iffy/dict_id_{_nbytes}byte.zst",
        ZstdFrameHeader(fhd=_fhd, content_size=struct.pack("<Q", 5), dict_id=_dict_id).pack()
        + ZstdBlockHeader(last_block=True, block_type=0, block_size=5).pack()
        + b"hello",
    )

# iffy/dict_id_zero_{2,4}byte.zst: dict_id=0 encoded in wider-than-necessary fields.
# RFC 8878: dict_id=0 means "no dictionary" regardless of field width, but a decoder could
# special-case only the 1-byte zero (already tested in accept/dict_id_zero.zst).
for _fhd, _dict_id in [
    (0xE2, b"\x00\x00"),                # 2-byte field, value=0
    (0xE3, b"\x00\x00\x00\x00"),        # 4-byte field, value=0
]:
    _nbytes = len(_dict_id)
    gen(
        f"iffy/dict_id_zero_{_nbytes}byte.zst",
        ZstdFrameHeader(fhd=_fhd, content_size=struct.pack("<Q", 5), dict_id=_dict_id).pack()
        + ZstdBlockHeader(last_block=True, block_type=0, block_size=5).pack()
        + b"hello",
    )

# --- Content_Size field != actual decompressed output ---

# malicious/declared_zero_with_content.zst: FCS_Flag=1 stored=0 → declared=256, actual=5 bytes.
# (FCS_Flag=1 adds 256 to stored value; stored 0 means declared 256, not 0.)
# FHD=0x60 (FCS_Flag=1), content_size=\x00\x00
gen(
    "malicious/declared_zero_with_content.zst",
    ZstdFrameHeader(fhd=0x60, content_size=struct.pack("<H", 0)).pack()
    + ZstdBlockHeader(last_block=True, block_type=0, block_size=5).pack()
    + b"hello",
)

# malicious/declared_wrong_size.zst: 2-byte content_size=10, actual output is 5 bytes
# (FCS_Flag=1, so stored 10 → declared 266; actual 5)
gen(
    "malicious/declared_wrong_size.zst",
    ZstdFrameHeader(fhd=0x60, content_size=struct.pack("<H", 10)).pack()
    + ZstdBlockHeader(last_block=True, block_type=0, block_size=5).pack()
    + b"hello",
)

# --- Window_Descriptor size variants (Single_Segment=0, FHD=0x00) ---
# Window_Descriptor byte: (Exponent << 3) | Mantissa
# Window_Size = (1 + Mantissa/8) << (10 + Exponent); spec max is 8 * 2^30 (~8.6 GB)

# iffy/window_16mb.zst: 0x70 → exponent=14, mantissa=0 → (1+0/8) << 24 = 16 MB
gen(
    "iffy/window_16mb.zst",
    ZstdFrameHeader(fhd=0x00, window_descriptor=0x70).pack()
    + ZstdBlockHeader(last_block=True, block_type=0, block_size=5).pack()
    + b"hello",
)

# iffy/window_1gb.zst: 0xA0 → exponent=20, mantissa=0 → (1+0/8) << 30 = 1 GB
gen(
    "iffy/window_1gb.zst",
    ZstdFrameHeader(fhd=0x00, window_descriptor=0xA0).pack()
    + ZstdBlockHeader(last_block=True, block_type=0, block_size=5).pack()
    + b"hello",
)

# reject/window_huge.zst: 0xFF → exponent=31, mantissa=7 → (15/8) << 41 ≈ 4 TB; exceeds spec 8 GB limit
gen(
    "reject/window_huge.zst",
    ZstdFrameHeader(fhd=0x00, window_descriptor=0xFF).pack()
    + ZstdBlockHeader(last_block=True, block_type=0, block_size=5).pack()
    + b"hello",
)

# reject/single_segment_huge.zst: Single_Segment=1 with FCS = 16 GB.
# For SSF=1, Window_Size = Frame_Content_Size, so this requires a 16 GB decoder
# window — above the 8 GB hard limit decoders must support.  Mirrors
# window_huge.zst but exercises the SSF path rather than Window_Descriptor.
gen(
    "reject/single_segment_huge.zst",
    simple_frame_header(16 * 1024 ** 3).pack()
    + ZstdBlockHeader(last_block=True, block_type=0, block_size=5).pack()
    + b"hello",
)

# malicious/block_exceeds_window.zst: Window_Descriptor=0x38 → 128 KB window.
# Block declares 256 KB = twice the window size — violates the spec invariant
# that block_size ≤ window_size (and ≤ 128 KB recommended max).
# 0x38 = exponent=7, mantissa=0 → (1+0/8) << (10+7) = 2^17 = 128 KB
_256k = 256 * 1024
gen(
    "malicious/block_exceeds_window.zst",
    ZstdFrameHeader(fhd=0x00, window_descriptor=0x38).pack()
    + ZstdBlockHeader(last_block=True, block_type=0, block_size=_256k).pack()
    + b"a" * _256k,
)

# malicious/rle_block_exceeds_max.zst: RLE_Block with Regenerated_Size=256 KB.
# Block_Maximum_Size = min(Window_Size, 128 KB); for a 1 MB window this is 128 KB.
# An RLE block's Block_Size field encodes Regenerated_Size, so 256 KB violates the limit.
# On-disk the payload is tiny (3-byte header + 1-byte body) but claims 256 KB of output.
# 0x50 = exponent=10, mantissa=0 → 2^20 = 1 MB window
gen(
    "malicious/rle_block_exceeds_max.zst",
    ZstdFrameHeader(fhd=0x00, window_descriptor=0x50).pack()
    + ZstdBlockHeader(last_block=True, block_type=1, block_size=_256k).pack()
    + b"a",
)

# --- Non-final-block variants: Last_Block=0 for each of the three block types ---
# These are iffy: the frame is never properly terminated, but some decoders
# may treat stream end as an implicit frame end.


def _frame_header_size(frame: bytes) -> int:
    """Return the byte length of a zstd frame header (magic + FHD + variable fields)."""
    fhd = frame[4]
    fcs_flag = (fhd >> 6) & 3
    single_segment = (fhd >> 5) & 1
    dict_id_flag = fhd & 3
    size = 5  # magic(4) + FHD(1)
    if not single_segment:
        size += 1  # Window_Descriptor
    size += [0, 1, 2, 4][dict_id_flag]
    size += [1 if single_segment else 0, 2, 4, 8][fcs_flag]
    return size


def _clear_last_block(frame: bytes) -> bytes:
    """Clear the Last_Block flag in the first block header of a complete zstd frame."""
    fhd = frame[4]
    fcs_flag = (fhd >> 6) & 3
    single_segment = (fhd >> 5) & 1
    dict_id_flag = fhd & 3
    offset = 5  # past magic (4B) + FHD (1B)
    if not single_segment:
        offset += 1  # Window_Descriptor
    offset += [0, 1, 2, 4][dict_id_flag]  # Dict_ID field
    offset += [1 if single_segment else 0, 2, 4, 8][fcs_flag]  # FCS field
    data = bytearray(frame)
    data[offset] &= 0xFE  # clear bit 0: Last_Block
    return bytes(data)


# iffy/no_final_raw.zst: Raw_Block (type 0) with Last_Block=0
gen(
    "iffy/no_final_raw.zst",
    simple_frame_header(5).pack()
    + ZstdBlockHeader(last_block=False, block_type=0, block_size=5).pack()
    + b"hello",
)

# iffy/no_final_rle.zst: RLE_Block (type 1) with Last_Block=0
gen(
    "iffy/no_final_rle.zst",
    simple_frame_header(5).pack()
    + ZstdBlockHeader(last_block=False, block_type=1, block_size=5).pack()
    + b"a",
)

# iffy/no_final_compressed.zst: Compressed_Block (type 2) with Last_Block=0.
# Take a real libzstd frame and patch the Last_Block bit to 0.
gen(
    "iffy/no_final_compressed.zst",
    _clear_last_block(compress(b"aaa" * 100)),
)

# reject/second_frame_oob_backref.zst: two-frame file where frame 2 was compressed
# using frame 1's content as a raw-content prefix. Frame 2's sequences contain
# back-reference offsets that reach into the prefix region — before frame 2's own
# decoded output begins. A decoder processing frame 2 without that prefix context
# will encounter an offset exceeding its available history and must reject.
_oob_prefix = b"abcdefghijklmnop" * 10  # 160 bytes
_oob_content = b"abcdefghijklmnop" * 3  # 48 bytes, fully matches start of prefix
gen(
    "reject/second_frame_oob_backref.zst",
    compress(_oob_prefix) + compress_with_prefix(_oob_content, _oob_prefix),
)

# reject/second_frame_dict_id_zero.zst: same OOB back-reference scenario, but
# frame 2 also carries an explicit Dict_ID_Flag=1 field with value=0. Per RFC 8878
# this means "no dictionary" — identical in effect to omitting the field — so the
# back-references are still out-of-bounds. Tests that decoders do not confuse
# explicit dict_id=0 with "use previous frame as context".
_raw_frame1 = compress(_oob_prefix)
_frame1_blocks = _raw_frame1[_frame_header_size(_raw_frame1):]
_raw_frame2 = compress_with_prefix(_oob_content, _oob_prefix)
_frame2_blocks = _raw_frame2[_frame_header_size(_raw_frame2):]
_dict_id_zero_fh = lambda size: ZstdFrameHeader(
    fhd=0xE1,  # FCS_Flag=3 (8B), Single_Segment=1, Dict_ID_Flag=1 (1B field)
    content_size=struct.pack("<Q", size),
    dict_id=b"\x00",
).pack()
gen(
    "reject/second_frame_dict_id_zero.zst",
    compress(_oob_prefix)
    + _dict_id_zero_fh(len(_oob_content))
    + _frame2_blocks,
)

# reject/both_frames_dict_id_zero.zst: like second_frame_dict_id_zero but frame 1
# also carries explicit dict_id=0. Tests the same decoder confusion in a context
# where neither frame gives the decoder a "clean" reference point.
gen(
    "reject/both_frames_dict_id_zero.zst",
    _dict_id_zero_fh(len(_oob_prefix))
    + _frame1_blocks
    + _dict_id_zero_fh(len(_oob_content))
    + _frame2_blocks,
)
