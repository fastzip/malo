# Deflate

This classic format works with essentially no allocations during decompressing.
A combination of Huffman coding and LZ77.

Review: kind of fiddly but pretty solid.  Two unallocated codes, and some
embiguity on end-of-stream that requires user to validate.

Smuggling: limited; up to 7 bits at end of compressed blocks, unnecessary
huffman codes you don't intend to use.  Use of those results in pretty obvious
negative compression ratio, limiting impact.  No way to skip data.  Block size
histogram will show excessive use of small blocks -- zlib generally commits to
~4k at a time even when storing.

Parallel decoding: requires precomputed offset table (and cooperating
compressor that discards accumulated window).

Scrambling: trivial, if you give all symbols 8-bit codes you can even choose
the mapping.
