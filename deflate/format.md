# Deflate layout

Deflate is not a container format in the archive sense. It is a raw block stream, and this corpus uses it both on its own and as the compressed payload inside ZIP.

## Top-level order

| Piece | Size | Count / order |
|---|---:|---|
| Block header | 3 bits minimum | One per block |
| Stored-block padding | 0-7 bits | Only for `BTYPE = 00` |
| Stored block length pair | 4 bytes | Only for `BTYPE = 00` |
| Stored block data | Variable | Only for `BTYPE = 00` |
| Fixed Huffman tables | Implicit | Only for `BTYPE = 01` |
| Dynamic Huffman header | Variable | Only for `BTYPE = 10` |
| Compressed symbols | Variable | Present for `BTYPE = 01` and `10` |

## Block structure

Every block starts with:

* `BFINAL` bit: 1 bit.
* `BTYPE`: 2 bits.

That means the first 3 bits determine the block class.

## Stored blocks

* `BTYPE = 00`.
* The stream first pads to the next byte boundary with zero bits.
* Then comes `LEN` and `NLEN`, each 16 bits little-endian.
* Then comes exactly `LEN` bytes of raw data.

## Fixed Huffman blocks

* `BTYPE = 01`.
* The literal/length alphabet is fixed.
* The distance alphabet is fixed.
* There is no per-block tree description.

## Dynamic Huffman blocks

* `BTYPE = 10`.
* The block header declares three counts:
  * `HLIT`: literal/length code count minus 257.
  * `HDIST`: distance code count minus 1.
  * `HCLEN`: code-length code count minus 4.
* Then the code-length alphabet is described in the fixed code order.
* Those code-length codes are then used to describe the literal/length and distance trees.
* The compressed payload follows after the trees are built.

## Structural limits

* One or more blocks per stream.
* Exactly one final block per stream, where `BFINAL = 1`.
* Stored blocks can be empty.
* Dynamic blocks must define valid trees; empty or oversubscribed trees are invalid.
* The symbol stream ends with the end-of-block code `256`.

## Typical counts

* One stream often contains one block, but multiple blocks are common.
* Stored-block payloads can be zero length.
* Dynamic headers appear once per dynamic block.
* Concatenated streams are outside the core deflate stream model and are a common differential trap.

## Compression behavior

* Best case: highly repetitive data can compress extremely well because one literal can be followed by many length/distance back-references.
* Deflate’s practical compression ratio is bounded by the 258-byte maximum match length and the 32 KiB distance window, but repeated runs and repeated substrings still compress very aggressively.
* On incompressible data, a good encoder should switch to stored blocks rather than emitting Huffman blocks that expand the payload.
* A stored block is essentially raw data with about 5 bytes of overhead per block, plus up to 7 bits of alignment padding before `LEN`/`NLEN`.
* If a compressor keeps using fixed or dynamic Huffman on random input, the result is usually larger than the input and should be treated as a poor encoder choice.
