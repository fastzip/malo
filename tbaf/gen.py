import hashlib
import json
import struct
import sys
import unicodedata
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_src"))

import tbafwoot
from zstdtypes import ZstdSkippableFrame, compress, compress_with_prefix


def sha256hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def gen(filename: str, data: bytes, meta: dict | None = None) -> None:
    path = Path(filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    meta_path = path.with_suffix(".json")
    if meta is not None:
        meta_path.write_text(json.dumps(meta, separators=(", ", ": ")) + "\n")
    elif meta_path.exists():
        meta_path.unlink()

# This one writes to .tbaf
def archive_file_entry(name: str, content: bytes, executable: bool = False, usize: int | None = None) -> dict:
    e = {"name": name, "usize": len(content) if usize is None else usize, "sha256": sha256hex(content)}
    if executable:
        e["x"] = True
    return e

# These are expected oracle output -- there might be some value in unifying --
# as you might guess, the oracle output heavily inspired the manifest format.
def file_meta(name: str, content: bytes, executable: bool = False) -> dict:
    m = {"member": name, "type": "file", "size": len(content), "sha256": sha256hex(content)}
    if executable:
        m["executable"] = True
    return m


def dir_meta(name: str) -> dict:
    return {"member": name, "type": "directory"}


def symlink_meta(name: str, target: str) -> dict:
    return {"member": name, "type": "symlink", "target": target}


HELLO = b"hello"

# accept/simple.tbaf: one regular file
gen(
    "accept/simple.tbaf",
    tbafwoot.build(dirs=[], files=[("hello.txt", HELLO, False)], symlinks=[]),
    {"expected": [file_meta("hello.txt", HELLO)]},
)

# accept/empty_file.tbaf: zero-byte file
gen(
    "accept/empty_file.tbaf",
    tbafwoot.build(dirs=[], files=[("empty.txt", b"", False)], symlinks=[]),
    {"expected": [file_meta("empty.txt", b"")]},
)

# accept/dir.tbaf: directory containing a file
gen(
    "accept/dir.tbaf",
    tbafwoot.build(
        dirs=["sub"],
        files=[("sub/hello.txt", HELLO, False)],
        symlinks=[],
    ),
    {"expected": [dir_meta("sub"), file_meta("sub/hello.txt", HELLO)]},
)

# accept/executable.tbaf: file with the execute bit set
gen(
    "accept/executable.tbaf",
    tbafwoot.build(dirs=[], files=[("run.sh", b"#!/bin/sh\n", True)], symlinks=[]),
    {"expected": [file_meta("run.sh", b"#!/bin/sh\n", executable=True)]},
)

# accept/nested_dirs.tbaf: parents listed before children
gen(
    "accept/nested_dirs.tbaf",
    tbafwoot.build(
        dirs=["a", "a/b"],
        files=[("a/b/deep.txt", HELLO, False)],
        symlinks=[],
    ),
    {"expected": [dir_meta("a"), dir_meta("a/b"), file_meta("a/b/deep.txt", HELLO)]},
)

# accept/empty_dir.tbaf: archive containing only an empty directory
gen(
    "accept/empty_dir.tbaf",
    tbafwoot.build(dirs=["emptydir"], files=[], symlinks=[]),
    {"expected": [dir_meta("emptydir")]},
)

# accept/symlink.tbaf: symlink whose target is a file in the archive
gen(
    "accept/symlink.tbaf",
    tbafwoot.build(
        dirs=[],
        files=[("hello.txt", HELLO, False)],
        symlinks=[("link.txt", "hello.txt")],
    ),
    {"expected": [file_meta("hello.txt", HELLO), symlink_meta("link.txt", "hello.txt")]},
)

# Reject

# Build a canonical valid archive to mangle their compressed streams
_valid = tbafwoot.build(dirs=[], files=[("hello.txt", HELLO, False)], symlinks=[])
_m_size = struct.unpack_from("<Q", _valid, 8)[0]
_cm_valid = _valid[tbafwoot.HEADER_SIZE : tbafwoot.HEADER_SIZE + _m_size]
_cc_valid = _valid[tbafwoot.HEADER_SIZE + _m_size :]

# reject/header_magic.tbaf
gen("reject/header_magic.tbaf", tbafwoot.assemble(_cm_valid, _cc_valid, magic=b"XXXX"))

# reject/header_compression.tbaf
gen("reject/header_compression.tbaf", tbafwoot.assemble(_cm_valid, _cc_valid, compression_field=b"gzip"))

# reject/header_manifest_checksum.tbaf: checksum field is all zeros
gen("reject/header_manifest_checksum.tbaf", tbafwoot.assemble(_cm_valid, _cc_valid, manifest_checksum=bytes(32)))

# reject/header_contents_checksum.tbaf: checksum field is all zeros
gen("reject/header_contents_checksum.tbaf", tbafwoot.assemble(_cm_valid, _cc_valid, contents_checksum=bytes(32)))

# reject/header_total_size.tbaf: header claims contents is 1 byte larger than it is
gen(
    "reject/header_total_size.tbaf",
    tbafwoot.assemble(_cm_valid, _cc_valid, contents_size=len(_cc_valid) + 1),
)

# reject/header_truncated.tbaf: file ends mid-header
gen("reject/header_truncated.tbaf", _valid[:40])


# Path violations — inject invalid names directly into manifest dicts.
def _reject_path(path: str) -> bytes:
    file_entries = [archive_file_entry(path, HELLO)]
    manifest = tbafwoot.encode_manifest([], file_entries, [])
    cm = tbafwoot.compress_single(manifest)
    cc = tbafwoot.compress_single(HELLO)
    return tbafwoot.assemble(cm, cc)


# reject/filename_nfd.tbaf: a single file whose name is NFD-encoded.
# Tests the NFC check in isolation — no collision partner needed.
gen("reject/filename_nfd.tbaf", _reject_path(unicodedata.normalize("NFD", "café.txt")))

# reject/filename_combining_order.tbaf: two filenames that differ only in the order of
# combining marks (i+U+0307+U+0323 vs i+U+0323+U+0307).  Both are non-NFC
# individually (U+0323 CCC=220 must precede U+0307 CCC=230, and the pair
# composes further to U+1ECB+U+0307).  Their NFC forms are identical, so a
# validator must normalize in the correct order BEFORE checking for duplicates.
_s1 = "ị̇"  # i + dot-above (U+0307, CCC 230) + dot-below (U+0323, CCC 220): wrong order
_s2 = "ị̇"  # i + dot-below (U+0323, CCC 220) + dot-above (U+0307, CCC 230): right order, but i+U+0323 composes
assert unicodedata.normalize("NFC", _s1) == unicodedata.normalize("NFC", _s2)
_manifest = tbafwoot.encode_manifest(
    [], [archive_file_entry(_s1, b"hello"), archive_file_entry(_s2, b"hello")], []
)
gen(
    "reject/filename_combining_order.tbaf",
    tbafwoot.assemble(tbafwoot.compress_single(_manifest), tbafwoot.compress_single(b"hellohello")),
)

gen("reject/filename_traversal.tbaf",        _reject_path("../../etc/passwd"))
gen("reject/filename_absolute.tbaf",         _reject_path("/etc/passwd"))
gen("reject/filename_backslash.tbaf",        _reject_path("dir\\file.txt"))
gen("reject/filename_colon.tbaf",            _reject_path("d:windows"))
gen("reject/filename_tilde.tbaf",            _reject_path("~/.bashrc"))
gen("reject/filename_dot_component.tbaf",    _reject_path("foo/./bar.txt"))
gen("reject/filename_dotdot_component.tbaf", _reject_path("foo/../bar.txt"))
gen("reject/filename_empty_component.tbaf",  _reject_path("foo//bar.txt"))
gen("reject/filename_trailing_dot.tbaf",     _reject_path("foo."))
gen("reject/filename_trailing_space.tbaf",   _reject_path("foo "))
gen("reject/filename_dot.tbaf",              _reject_path("."))
gen("reject/filename_dotdot.tbaf",           _reject_path(".."))

# reject/filename_dupe.tbaf: same path twice in the files list
_manifest = tbafwoot.encode_manifest(
    [],
    [archive_file_entry("same.txt", b"hello"), archive_file_entry("same.txt", b" world!")],
    [],
)
gen(
    "reject/filename_dupe.tbaf",
    tbafwoot.assemble(tbafwoot.compress_single(_manifest), tbafwoot.compress_single(b"hello world!")),
)

# reject/filename_dupe_cross.tbaf: same path in dirs and files
_manifest = tbafwoot.encode_manifest(
    [{"name": "foo"}],
    [archive_file_entry("foo", HELLO)],
    [],
)
gen(
    "reject/filename_dupe_cross.tbaf",
    tbafwoot.assemble(tbafwoot.compress_single(_manifest), tbafwoot.compress_single(HELLO)),
)

# reject/filename_case_collision.tbaf: "Foo.txt" and "foo.txt" collide under casefold
_manifest = tbafwoot.encode_manifest(
    [],
    [archive_file_entry("Foo.txt", b"hello"), archive_file_entry("foo.txt", b"hello")],
    [],
)
gen(
    "reject/filename_case_collision.tbaf",
    tbafwoot.assemble(tbafwoot.compress_single(_manifest), tbafwoot.compress_single(b"hellohello")),
)

# reject/manifest_dir_missing.tbaf: file path references a directory not in dirs list
_manifest = tbafwoot.encode_manifest([], [archive_file_entry("subdir/hello.txt", HELLO)], [])
gen(
    "reject/manifest_dir_missing.tbaf",
    tbafwoot.assemble(tbafwoot.compress_single(_manifest), tbafwoot.compress_single(HELLO)),
)

# reject/manifest_multi_frame.tbaf: manifest stream contains two zstd frames
_manifest = tbafwoot.encode_manifest([], [archive_file_entry("hello.txt", HELLO)], [])
_mid = len(_manifest) // 2
_multi_cm = tbafwoot.compress_single(_manifest[:_mid]) + tbafwoot.compress_single(_manifest[_mid:])
gen("reject/manifest_multi_frame.tbaf", tbafwoot.assemble(_multi_cm, _cc_valid))

# reject/manifest_sha256_missing.tbaf: file metadata omits the required hash field
_manifest = tbafwoot.encode_manifest([], [{"name": "hello.txt", "usize": 5}], [])
gen(
    "reject/manifest_sha256_missing.tbaf",
    tbafwoot.assemble(tbafwoot.compress_single(_manifest), tbafwoot.compress_single(HELLO)),
)

# reject/manifest_symlink_unknown_target.tbaf: target not present in dirs or files
_manifest = tbafwoot.encode_manifest([], [], [{"name": "link.txt", "target": "nonexistent.txt"}])
gen(
    "reject/manifest_symlink_unknown_target.tbaf",
    tbafwoot.assemble(tbafwoot.compress_single(_manifest), tbafwoot.compress_single(b"")),
)

# reject/manifest_symlink_chain.tbaf: link2 targets link1 which is a symlink, not a file/dir
_manifest = tbafwoot.encode_manifest(
    [],
    [archive_file_entry("hello.txt", HELLO)],
    [{"name": "link1.txt", "target": "hello.txt"}, {"name": "link2.txt", "target": "link1.txt"}],
)
gen(
    "reject/manifest_symlink_chain.tbaf",
    tbafwoot.assemble(tbafwoot.compress_single(_manifest), tbafwoot.compress_single(HELLO)),
)

# reject/contents_usize_mismatch.tbaf: manifest claims 999 bytes but stream only has 5
_manifest = tbafwoot.encode_manifest([], [archive_file_entry("hello.txt", HELLO, usize=999)], [])
gen(
    "reject/contents_usize_mismatch.tbaf",
    tbafwoot.assemble(tbafwoot.compress_single(_manifest), tbafwoot.compress_single(HELLO)),
)

# reject/contents_sha256_mismatch.tbaf: file metadata includes a hash that does not match
# the extracted file contents.
_manifest = tbafwoot.encode_manifest(
    [],
    [{"name": "hello.txt", "usize": 5, "sha256": "0" * 64}],
    [],
)
gen(
    "reject/contents_sha256_mismatch.tbaf",
    tbafwoot.assemble(tbafwoot.compress_single(_manifest), tbafwoot.compress_single(HELLO)),
)

# reject/contents_file_split_across_frames.tbaf: one logical file is split across two
# contents frames, so the second frame begins in the middle of the file.
_manifest = tbafwoot.encode_manifest(
    [],
    [{"name": "hello.txt", "usize": 5, "sha256": sha256hex(HELLO)}],
    [],
)
gen(
    "reject/contents_file_split_across_frames.tbaf",
    tbafwoot.assemble(tbafwoot.compress_single(_manifest), compress(b"hel") + compress(b"lo")),
)

# accept/cpos_redundant.tbaf: first file carries cpos=0 explicitly.
# This is redundant (the first file always starts at offset 0) but must be
# accepted.  According to the spec, it's "redundant and harmless".
gen(
    "accept/cpos_redundant.tbaf",
    tbafwoot.assemble(
        tbafwoot.compress_single(tbafwoot.encode_manifest(
            [], [{**archive_file_entry("hello.txt", HELLO), "cpos": 0}], []
        )),
        tbafwoot.compress_single(HELLO),
    ),
    {"expected": [file_meta("hello.txt", HELLO)]},
)

# accept/cpos.tbaf: two files in two separate zstd frames; the second
# file carries cpos pointing to the start of its frame.
_frame1 = tbafwoot.compress_single(HELLO)
_frame2 = tbafwoot.compress_single(b"world")
_cpos2 = len(_frame1)
gen(
    "accept/cpos.tbaf",
    tbafwoot.assemble(
        tbafwoot.compress_single(tbafwoot.encode_manifest(
            [],
            [archive_file_entry("hello.txt", HELLO),
             {**archive_file_entry("world.txt", b"world"), "cpos": _cpos2}],
            [],
        )),
        _frame1 + _frame2,
    ),
    {"expected": [file_meta("hello.txt", HELLO), {**file_meta("world.txt", b"world"), "cpos": _cpos2}]},
)

# reject/cpos_out_of_range.tbaf: cpos ≥ compressed contents size.
_cc3 = tbafwoot.compress_single(b"hellohellohello")
gen(
    "reject/cpos_out_of_range.tbaf",
    tbafwoot.assemble(
        tbafwoot.compress_single(tbafwoot.encode_manifest(
            [],
            [archive_file_entry("a.txt", b"hello"),
             {**archive_file_entry("b.txt", b"hello"), "cpos": len(_cc3)},  # == c_size, out of range
             archive_file_entry("c.txt", b"hello")],
            [],
        )),
        _cc3,
    ),
)

# reject/cpos_decreasing.tbaf: cpos values not strictly increasing.
_cc3_mid = len(_cc3) // 2
gen(
    "reject/cpos_decreasing.tbaf",
    tbafwoot.assemble(
        tbafwoot.compress_single(tbafwoot.encode_manifest(
            [],
            [archive_file_entry("a.txt", b"hello"),
             {**archive_file_entry("b.txt", b"hello"), "cpos": _cc3_mid},
             {**archive_file_entry("c.txt", b"hello"), "cpos": _cc3_mid - 1}],
            [],
        )),
        _cc3,
    ),
)

# reject/cpos_duplicate.tbaf: two files with the same cpos value.
gen(
    "reject/cpos_duplicate.tbaf",
    tbafwoot.assemble(
        tbafwoot.compress_single(tbafwoot.encode_manifest(
            [],
            [archive_file_entry("a.txt", b"hello"),
             {**archive_file_entry("b.txt", b"hello"), "cpos": _cc3_mid},
             {**archive_file_entry("c.txt", b"hello"), "cpos": _cc3_mid}],
            [],
        )),
        _cc3,
    ),
)

# reject/contents_frame_history_bleed.tbaf: the second content frame was
# compressed with the first frame's payload as a raw prefix. A decoder that
# incorrectly carries history across frame boundaries may accept it, but TBAF
# contents are frame-independent.
_history_prefix = b"abcdefghijklmnop" * 10  # 160 bytes
_history_suffix = b"abcdefghijklmnop" * 3  # 48 bytes
_manifest = tbafwoot.encode_manifest(
    [],
    [
        archive_file_entry("prefix.bin", _history_prefix),
        archive_file_entry("suffix.bin", _history_suffix),
    ],
    [],
)
gen(
    "reject/contents_frame_history_bleed.tbaf",
    tbafwoot.assemble(
        tbafwoot.compress_single(_manifest),
        compress(_history_prefix) + compress_with_prefix(_history_suffix, _history_prefix),
    ),
)

# reject/contents_skippable_frame.tbaf: a skippable frame is smuggled into the
# contents stream between two real frames. RFC 8878 says decoders skip these,
# but TBAF should treat them as invalid content bytes.
_manifest = tbafwoot.encode_manifest(
    [],
    [
        archive_file_entry("first.bin", b"hello"),
        archive_file_entry("second.bin", b"world"),
    ],
    [],
)
gen(
    "reject/contents_skippable_frame.tbaf",
    tbafwoot.assemble(
        tbafwoot.compress_single(_manifest),
        compress(b"hello") + ZstdSkippableFrame(data=b"smuggled").pack() + compress(b"world"),
    ),
)

# Malicious

# malicious/unicode_normalization.tbaf: two file entries whose names are the same
# codepoint sequence in NFC vs NFD.  Both pass UTF-8 validation and neither
# path component ends in a dot/space, but they collide after NFC normalization.
# A strict decoder must normalize and reject; a lax one may extract both,
# with the second overwriting the first on any NFC-normalizing filesystem.
_nfc = unicodedata.normalize("NFC", "café.txt")  # é = U+00E9 (1 codepoint)
_nfd = unicodedata.normalize("NFD", "café.txt")  # é = e + U+0301 (2 codepoints)
assert _nfc != _nfd
_manifest = tbafwoot.encode_manifest(
    [],
    [archive_file_entry(_nfc, b"hello"), archive_file_entry(_nfd, b" world!")],
    [],
)
gen(
    "malicious/unicode_normalization.tbaf",
    tbafwoot.assemble(
        tbafwoot.compress_single(_manifest),
        tbafwoot.compress_single(b"hello world!"),
    ),
    {"vulnerable_when": [{"member": _nfd}]},
)
