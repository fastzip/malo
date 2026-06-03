# Zstandard layout

This corpus treats a Zstd file as a sequence of independent records. The important layers are: magic, frame header, zero or more blocks, optional checksum, then optionally another frame or a skippable frame.

## Top-level order

| Piece | Size | Count / order |
|---|---:|---|
| Frame magic | 4 bytes | One per normal frame |
| Frame header descriptor | 1 byte | One per normal frame |
| Window descriptor | 0 or 1 byte | Present when `Single_Segment = 0` |
| Dictionary ID | 0, 1, 2, or 4 bytes | Present when the header requests it |
| Content size | 0, 2, 4, or 8 bytes | Present according to the FCS flag; mandatory for single-segment frames |
| Block headers | 3 bytes each | One per block |
| Block payload | Variable | Immediately after each block header |
| Frame checksum | 4 bytes | Optional, only when the checksum flag is set |
| Skippable frame | 8 bytes + payload | Independent record that can appear anywhere between frames |

## Core record sizes

| Record | Size | Notes |
|---|---:|---|
| `ZstdBlockHeader` | 3 bytes | 21-bit block size plus a 2-bit block type and 1-bit final flag |
| `ZstdFrameHeader` | Variable | The code models the header as `magic` + `fhd` + optional window byte + raw dict/content bytes |
| `ZstdSkippableFrame` | 8 bytes + payload | 4-byte magic in the skippable range, then 4-byte little-endian payload length |

## Block nesting

* A frame contains one or more blocks.
* Each block starts with a 3-byte little-endian header.
* The header carries the final-block bit, the block type, and the block size.
* The payload immediately follows and its interpretation depends on the block type:
  * Raw block: `block_size` literal bytes.
  * RLE block: one byte repeated `block_size` times.
  * Compressed block: entropy-coded payload.
  * Reserved block type: invalid.

## Frame-header structure

The frame header is variable-length.

* One byte of magic descriptor follows the 4-byte magic.
* The descriptor controls whether a window byte is present, whether a checksum follows the frame, whether a dictionary ID is present, and how wide the content-size field is.
* `Single_Segment = 1` means there is no window descriptor and the content size is required.
* `Single_Segment = 0` means the window descriptor is present, and content size may be omitted depending on the FCS flag.
* The repo’s helper functions treat the optional fields as raw bytes; this is useful for malformed fixtures.

## Skippable frames

* A skippable frame is not a normal data frame.
* Its magic is any value in `0x184D2A50..0x184D2A5F`.
* It is followed by a 4-byte payload length and then that many bytes of uninterpreted data.
* Multiple skippable frames are allowed.

## Typical counts

* One normal frame or more than one concatenated frame are both possible.
* One or more blocks per frame.
* Exactly one final block per frame, marked by the final bit.
* Zero or one checksum per frame.
* Zero or more skippable frames between normal frames.

## Compression behavior

* Best case: highly repetitive input can compress to a tiny fraction of its original size, especially with `RLE_Block`s or long back-references in `Compressed_Block`s.
* There is no meaningful fixed "maximum ratio" at the frame level; the practical ceiling is driven by block-size limits, framing overhead, and whether the encoder can reuse repeats effectively.
* On incompressible input, a good encoder should usually emit `Raw_Block`s rather than forcing entropy coding.
* `Raw_Block`s still cost 3 bytes of block header each, plus the fixed frame-header overhead once per frame.
* If the encoder insists on compressing random data, the result is typically larger than the input and is just wasted work.
