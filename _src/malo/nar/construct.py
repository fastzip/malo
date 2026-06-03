"""
narwoot: NAR (Nix ARchive) builder with intentional-malformation support.

NAR wire format
---------------
Every "string" is:
    uint64-LE length        (8 bytes)
    raw bytes               (length bytes)
    null padding            (0–7 bytes so total is aligned to 8)

A complete archive is:
    str "nix-archive-1"
    <node>

where <node> is one of:
    regular   := "(" "type" "regular" ["executable" ""] "contents" <data> ")"
    directory := "(" "type" "directory" [entry ...] ")"
    symlink   := "(" "type" "symlink" "target" <target> ")"
    entry     := "entry" "(" "name" <name> "node" <node> ")"

Entries in a directory MUST be in strict lexicographic order by name,
and names MUST be unique.

Usage
-----
    from malo.nar.construct import s, nar, regular, directory, directory_raw, symlink

Low-level token:
    s("hello")   # → bytes: 8-byte LE length + data + null padding
    s(b"hello")  # same, bytes input

Well-formed nodes (return bytes):
    regular(content=b"", executable=False)
    directory(entries)      # list of (name, node_bytes); auto-sorted by name
    symlink(target)

Malformed helpers:
    directory_raw(entries)  # same as directory() but does not sort entries
                            # useful for wrong-order and duplicate-name cases
"""

import struct
from typing import Iterable

NAR_MAGIC = b"nix-archive-1"


def s(data: bytes | str) -> bytes:
    """Encode data as a NAR string token: uint64-LE length + bytes + null padding."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    n = len(data)
    pad = (8 - n % 8) % 8
    return struct.pack("<Q", n) + data + b"\x00" * pad


def regular(content: bytes = b"", executable: bool = False) -> bytes:
    """Well-formed regular file node bytes."""
    out = s("(") + s("type") + s("regular")
    if executable:
        out += s("executable") + s("")
    out += s("contents") + s(content) + s(")")
    return out


def symlink(target: str | bytes) -> bytes:
    """Well-formed symlink node bytes."""
    return s("(") + s("type") + s("symlink") + s("target") + s(target) + s(")")


def _entry(name: str | bytes, node_bytes: bytes) -> bytes:
    """Single 'entry (name <n> node <node> )' block."""
    return s("entry") + s("(") + s("name") + s(name) + s("node") + node_bytes + s(")")


def directory(entries: Iterable[tuple[str | bytes, bytes]]) -> bytes:
    """Well-formed directory node bytes. Entries are sorted lexicographically by name."""
    entry_list = sorted(
        entries,
        key=lambda e: (e[0].encode() if isinstance(e[0], str) else e[0]),
    )
    out = s("(") + s("type") + s("directory")
    for name, node_bytes in entry_list:
        out += _entry(name, node_bytes)
    out += s(")")
    return out


def directory_raw(entries: Iterable[tuple[str | bytes, bytes]]) -> bytes:
    """Directory node bytes WITHOUT sorting. For malformed archives.

    Use this to create wrong-order entries, duplicate names, or
    name collisions between a file and a directory.
    """
    out = s("(") + s("type") + s("directory")
    for name, node_bytes in entries:
        out += _entry(name, node_bytes)
    out += s(")")
    return out


def nar(root_node: bytes) -> bytes:
    """Wrap a root node into a complete NAR archive."""
    return s(NAR_MAGIC) + root_node
