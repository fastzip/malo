#!/usr/bin/env python3
"""
Reference oracle for Tim's Boring AF (TBAF) archives.

Exit 0 + JSON member lines on stdout  →  valid
Exit 1 + error on stderr              →  invalid archive
Exit 2 + error on stderr              →  I/O or oracle error
"""
import hashlib
import json
import struct
import sys
import unicodedata

import zstandard

MAGIC = b"B\x00RE"
COMPRESSION = b"zstd"
HEADER_SIZE = 88
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
ZSTD_MAGIC_U32 = struct.unpack("<I", ZSTD_MAGIC)[0]
ZSTD_SKIPPABLE_MAGIC_MIN = 0x184D2A50
ZSTD_SKIPPABLE_MAGIC_MAX = 0x184D2A5F

# NUL, backslash, BOM (U+FEFF), colon, tilde
_FORBIDDEN = frozenset({chr(0), "\\", chr(0xFEFF), ":", "~"})


def _reject(msg: str) -> None:
    print(msg, file=sys.stderr)
    sys.exit(1)


def _validate_path(path: object, seen: set[str], label: str) -> str:
    if not isinstance(path, str):
        _reject(f"{label}: path must be a string, got {type(path).__name__}")
    if not path:
        _reject(f"{label}: empty path")
    if any(ch in _FORBIDDEN for ch in path):
        _reject(f"{label}: forbidden character in {path!r}")
    if any("\ud800" <= ch <= "\udfff" for ch in path):
        _reject(f"{label}: surrogate in {path!r}")
    if path != unicodedata.normalize("NFC", path):
        _reject(f"{label}: path not NFC-normalized: {path!r}")
    if path.startswith("/"):
        _reject(f"{label}: absolute path: {path!r}")
    for part in path.split("/"):
        if part in ("", ".", ".."):
            _reject(f"{label}: forbidden component {part!r} in {path!r}")
        if part.endswith((".", " ")):
            _reject(f"{label}: component ends with dot or space in {path!r}")
    folded = path.casefold()
    if folded in seen:
        _reject(f"{label}: case-folded duplicate: {path!r}")
    seen.add(folded)
    return path


def _iter_zstd_frames(data: bytes, label: str):
    """Yield (cpos, magic, decompressed_bytes) for each ordinary zstd frame.

    Cursor-based: advances by the consumed frame length at each step and rejects
    any skippable record encountered at the current position.
    """
    cpos = 0
    upos = 0
    while cpos < len(data):
        if len(data) - cpos < 4:
            _reject(f"{label}: truncated before frame magic at cpos={cpos}, upos={upos}")

        magic, = struct.unpack_from("<I", data, cpos)
        if ZSTD_SKIPPABLE_MAGIC_MIN <= magic <= ZSTD_SKIPPABLE_MAGIC_MAX:
            _reject(f"{label}: skippable frame not allowed at cpos={cpos}, upos={upos}")
        if magic != ZSTD_MAGIC_U32:
            _reject(f"{label}: bad frame magic 0x{magic:08x} at cpos={cpos}, upos={upos}")

        decomp = zstandard.ZstdDecompressor().decompressobj()
        try:
            frame_out = decomp.decompress(data[cpos:])
        except zstandard.ZstdError as e:
            _reject(f"{label}: decompression failed at cpos={cpos}, upos={upos}: {e}")
        if not decomp.eof:
            _reject(f"{label}: truncated frame at cpos={cpos}, upos={upos}")

        consumed = len(data[cpos:]) - len(decomp.unused_data)
        if consumed <= 0:
            _reject(f"{label}: decoder made no progress at cpos={cpos}, upos={upos}")

        yield cpos, magic, frame_out
        cpos += consumed
        upos += len(frame_out)


def _validate_frame_starts(upos_starts: list[int], file_boundaries: set[int], label: str) -> None:
    """Ensure each contents-frame boundary (in uncompressed space) lands at a file boundary."""
    for idx, upos in enumerate(upos_starts[1:], start=1):
        if upos not in file_boundaries:
            _reject(f"{label}: frame start at uncompressed offset {upos} splits a file")


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(f"Usage: {sys.argv[0]} <file>")

    try:
        raw = open(sys.argv[1], "rb").read()
    except OSError as e:
        print(e, file=sys.stderr)
        sys.exit(2)

    # ── Fixed header ─────────────────────────────────────────────────────────

    if len(raw) < HEADER_SIZE:
        _reject(f"truncated: {len(raw)} < {HEADER_SIZE} bytes")
    if raw[:4] != MAGIC:
        _reject(f"bad magic: {raw[:4]!r}")
    if raw[4:8] != COMPRESSION:
        _reject(f"unknown compression: {raw[4:8]!r}")

    m_size, = struct.unpack_from("<Q", raw, 8)
    m_sum   = raw[16:48]
    c_size, = struct.unpack_from("<Q", raw, 48)
    c_sum   = raw[56:88]

    expected = HEADER_SIZE + m_size + c_size
    if len(raw) != expected:
        _reject(f"size mismatch: header says {expected}, file is {len(raw)}")

    cm = raw[HEADER_SIZE : HEADER_SIZE + m_size]
    cc = raw[HEADER_SIZE + m_size :]

    if hashlib.sha256(cm).digest() != m_sum:
        _reject("manifest checksum mismatch")
    if hashlib.sha256(cc).digest() != c_sum:
        _reject("contents checksum mismatch")

    # ── Manifest ─────────────────────────────────────────────────────────────

    manifest_frames = list(_iter_zstd_frames(cm, "manifest"))
    if len(manifest_frames) != 1:
        _reject(f"manifest: must be exactly one frame, got {len(manifest_frames)}")
    _, _, manifest_bytes = manifest_frames[0]

    try:
        manifest = json.loads(manifest_bytes)
    except Exception as e:
        _reject(f"manifest: JSON decode failed: {e}")

    if not isinstance(manifest, list) or len(manifest) != 3:
        _reject("manifest: must be a 3-element list")

    dirs_raw, files_raw, symlinks_raw = manifest

    if not isinstance(dirs_raw, list):
        _reject("manifest[0] (dirs) must be a list")
    if not isinstance(files_raw, list):
        _reject("manifest[1] (files) must be a list")
    if not isinstance(symlinks_raw, list):
        _reject("manifest[2] (symlinks) must be a list")

    seen: set[str] = set()   # case-folded paths across all three sections
    dir_set: set[str] = set()
    file_set: set[str] = set()

    # Dirs
    for i, entry in enumerate(dirs_raw):
        if not isinstance(entry, dict) or "name" not in entry:
            _reject(f"dir[{i}]: must be a dict with 'name'")
        name = _validate_path(entry["name"], seen, f"dir[{i}]")
        parent = name.rsplit("/", 1)[0] if "/" in name else None
        if parent is not None and parent not in dir_set:
            _reject(f"dir[{i}] {name!r}: parent {parent!r} not yet declared")
        dir_set.add(name)

    # Files
    file_entries: list[tuple[str, int, bool, str, int | None]] = []  # name, usize, exec, sha256, cpos
    file_boundaries: set[int] = set()
    last_cpos = -1
    file_offset = 0

    for i, entry in enumerate(files_raw):
        if not isinstance(entry, dict):
            _reject(f"files[{i}]: must be a dict")
        if "name" not in entry or "usize" not in entry:
            _reject(f"files[{i}]: missing 'name' or 'usize'")
        if "sha256" not in entry:
            _reject(f"files[{i}]: missing 'sha256'")
        usize = entry["usize"]
        if not isinstance(usize, int) or usize < 0:
            _reject(f"files[{i}]: usize must be a non-negative integer")
        sha256 = entry["sha256"]
        if not isinstance(sha256, str):
            _reject(f"files[{i}]: sha256 must be a string")
        x = entry.get("x")
        if x is not None and x is not True:
            _reject(f"files[{i}]: 'x' must be true if present, got {x!r}")
        cpos = entry.get("cpos")
        if cpos is not None:
            if not isinstance(cpos, int) or cpos < 0:
                _reject(f"files[{i}]: cpos must be a non-negative integer")
            if cpos >= c_size:
                _reject(f"files[{i}]: cpos {cpos} is out of range (contents is {c_size} bytes)")
            if cpos <= last_cpos:
                _reject(f"files[{i}]: cpos {cpos} not strictly increasing (prev {last_cpos})")
            last_cpos = cpos
        name = _validate_path(entry["name"], seen, f"files[{i}]")
        parent = name.rsplit("/", 1)[0] if "/" in name else None
        if parent is not None and parent not in dir_set:
            _reject(f"files[{i}] {name!r}: parent dir {parent!r} not declared")
        file_set.add(name)
        file_entries.append((name, usize, x is True, sha256, cpos))
        file_offset += usize
        file_boundaries.add(file_offset)

    # Symlinks
    for i, entry in enumerate(symlinks_raw):
        if not isinstance(entry, dict) or "name" not in entry or "target" not in entry:
            _reject(f"symlinks[{i}]: must be a dict with 'name' and 'target'")
        target = entry["target"]
        if not isinstance(target, str):
            _reject(f"symlinks[{i}]: target must be a string")
        name = _validate_path(entry["name"], seen, f"symlinks[{i}]")
        if target not in dir_set and target not in file_set:
            _reject(f"symlinks[{i}] {name!r}: target {target!r} not in dirs or files")

    # ── Contents ─────────────────────────────────────────────────────────────

    contents = bytearray()
    upos_starts: list[int] = []
    upos = 0
    for _, _, frame_out in _iter_zstd_frames(cc, "contents"):
        upos_starts.append(upos)
        contents.extend(frame_out)
        upos += len(frame_out)
    contents = bytes(contents)
    _validate_frame_starts(upos_starts, file_boundaries, "contents")

    total_usize = sum(usize for _, usize, _, _, _ in file_entries)
    if len(contents) != total_usize:
        _reject(f"contents size mismatch: usizes sum to {total_usize}, decompressed {len(contents)}")

    # ── Output ───────────────────────────────────────────────────────────────

    for entry in dirs_raw:
        print(json.dumps({"member": entry["name"], "type": "directory"}, separators=(",", ":")))

    offset = 0
    for name, usize, executable, expected_sha256, cpos in file_entries:
        chunk = contents[offset : offset + usize]
        actual_sha256 = hashlib.sha256(chunk).hexdigest()
        if actual_sha256 != expected_sha256:
            _reject(
                f"file hash mismatch for {name!r}: manifest {expected_sha256}, actual {actual_sha256}"
            )
        rec: dict = {
            "member": name,
            "type": "file",
            "size": usize,
            "sha256": actual_sha256,
        }
        if cpos is not None:
            rec["cpos"] = cpos
        if executable:
            rec["executable"] = True
        print(json.dumps(rec, separators=(",", ":")))
        offset += usize

    for entry in symlinks_raw:
        print(json.dumps({"member": entry["name"], "type": "symlink", "target": entry["target"]}, separators=(",", ":")))

    sys.exit(0)


if __name__ == "__main__":
    main()
