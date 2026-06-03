"""
zarwoot: builder for ZAR archives.

Binary layout (88-byte fixed header):
  [0:4]   b"B\\0RE"       magic
  [4:8]   b"zstd"         compression algorithm
  [8:16]  uint64-le       compressed manifest size (a)
  [16:48] bytes[32]       SHA-256 of compressed manifest
  [48:56] uint64-le       compressed contents size (b)
  [56:88] bytes[32]       SHA-256 of compressed contents
  [88:88+a]               compressed manifest  (one or more zstd frames)
  [88+a:88+a+b]           compressed contents  (one or more zstd frames)

Manifest is a JSON-encoded (UTF-8) 3-element list [dirs, files, symlinks]:
  dirs:     [{"name": str}, ...]
  files:    [{"name": str, "usize": int, "sha256": str, "x"?: true,
              "frame_start"?: int}, ...]
  symlinks: [{"name": str, "target": str}, ...]

Low-level entry points for building malformed archives:
  encode_manifest(dirs, file_entries, symlinks) -> bytes
  compress_single(data) -> bytes
  assemble(cm, cc, **overrides) -> bytes

High-level entry point for well-formed archives:
  build(dirs, files, symlinks) -> bytes
"""

import hashlib
import struct

import json

import zstandard  # python-zstandard; swap for compression.zstd on Python 3.14+

MAGIC = b"B\x00RE"
COMPRESSION = b"zstd"
HEADER_SIZE = 88


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def compress_single(data: bytes, level: int = 3) -> bytes:
    """Compress data as a single complete zstd frame."""
    return zstandard.ZstdCompressor(level=level).compress(data)


def encode_manifest(
    dirs: list[dict],
    file_entries: list[dict],
    symlinks: list[dict],
) -> bytes:
    """Encode the three manifest sections as compact UTF-8 JSON.

    All dicts are passed through directly, so callers can inject malformed
    keys/values without going through build().
    """
    return json.dumps([dirs, file_entries, symlinks], separators=(",", ":")).encode("utf-8")


PADDING = b"\xff\xff\xff\xff"


def assemble(
    compressed_manifest: bytes,
    compressed_contents: bytes,
    *,
    magic: bytes = MAGIC,
    compression_field: bytes = COMPRESSION,
    manifest_checksum: bytes | None = None,
    manifest_size: int | None = None,
    contents_checksum: bytes | None = None,
    contents_size: int | None = None,
    padding: bytes = PADDING,
) -> bytes:
    """Assemble a ZAR archive from pre-compressed streams.

    Keyword arguments override the auto-computed header fields, letting callers
    introduce specific header malformations without touching the stream data.
    """
    m_sum = _sha256(compressed_manifest) if manifest_checksum is None else manifest_checksum
    c_sum = _sha256(compressed_contents) if contents_checksum is None else contents_checksum
    m_size = len(compressed_manifest) if manifest_size is None else manifest_size
    c_size = len(compressed_contents) if contents_size is None else contents_size

    header = (
        magic
        + compression_field
        + struct.pack("<Q", m_size)
        + m_sum
        + struct.pack("<Q", c_size)
        + c_sum
    )
    assert len(header) == HEADER_SIZE
    return header + compressed_manifest + padding + compressed_contents


def build(
    dirs: list[str],
    files: list[tuple[str, bytes, bool]],
    symlinks: list[tuple[str, str]],
) -> bytes:
    """Build a well-formed ZAR archive.

    dirs:     directory path strings, parents before children
    files:    (name, content, executable) triples
    symlinks: (name, target) pairs; target must name a dir or file listed above
    """
    dir_entries = [{"name": d} for d in dirs]

    file_entries: list[dict] = []
    contents = b""
    for name, content, executable in files:
        e: dict = {"name": name, "usize": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        if executable:
            e["x"] = True
        file_entries.append(e)
        contents += content

    symlink_entries = [{"name": n, "target": t} for n, t in symlinks]

    manifest_bytes = encode_manifest(dir_entries, file_entries, symlink_entries)
    cm = compress_single(manifest_bytes)
    cc = compress_single(contents)
    return assemble(cm, cc)
