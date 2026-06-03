# Zstd

Better than deflate in both compression ratio and decompression speed, although
requiring more memory.

Review

Smuggling: easy, with skippable frames


Parallel decoding: built-in to libzstd, although you can't change the number of
threads at runtime.  Context init is a little expensive due to preallocating.

Scrambling: haven't tried
