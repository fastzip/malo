import hashlib
import json
import struct
import sys
import unicodedata
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_src"))

from malo.zar import construct as zarwoot
from malo.zstd.construct import ZstdSkippableFrame, compress, compress_with_prefix


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


def file_meta(name: str, content: bytes, executable: bool = False) -> dict:
    m = {"member": name, "type": "file", "size": len(content), "sha256": sha256hex(content)}
    if executable:
        m["executable"] = True
    return m


def dir_meta(name: str) -> dict:
    return {"member": name, "type": "directory"}


def symlink_meta(name: str, target: str) -> dict:
    return {"member": name, "type": "symlink", "target": target}


def archive_file_entry(name: str, content: bytes, executable: bool = False, usize: int | None = None) -> dict:
    e = {"name": name, "usize": len(content) if usize is None else usize, "sha256": sha256hex(content)}
    if executable:
        e["x"] = True
    return e


def make_zstd_single_segment_rle(byte_val: int, total_size: int) -> bytes:
    """Build a minimal valid single-segment zstd frame of total_size repetitions of byte_val.

    Uses RLE blocks (4 bytes each) so the output is ~2 KB regardless of total_size.
    Single_Segment_Flag=1 means Window_Size = Frame_Content_Size = total_size.
    """
    MAX_RLE = (1 << 21) - 1  # 2097151, max content size per zstd RLE block
    # FHD byte: FCS_flag=2 (4-byte FCS), SSF=1, no checksum, no dict = 0xA0
    fhd = b"\xa0"
    fcs = struct.pack("<I", total_size)
    blocks = bytearray()
    remaining = total_size
    while remaining > 0:
        n = min(remaining, MAX_RLE)
        remaining -= n
        is_last = 1 if remaining == 0 else 0
        # Block_Header: bits 0=Last, bits 2-1=Type(01=RLE), bits 23-3=Size
        header_val = (n << 3) | (0b01 << 1) | is_last
        blocks += struct.pack("<I", header_val)[:3]
        blocks.append(byte_val)
    return b"\x28\xb5\x2f\xfd" + fhd + fcs + bytes(blocks)


HELLO = b"hello"

# ── accept ────────────────────────────────────────────────────────────────────

# accept/simple.zar: one regular file
gen(
    "accept/simple.zar",
    zarwoot.build(dirs=[], files=[("hello.txt", HELLO, False)], symlinks=[]),
    {"expected": [file_meta("hello.txt", HELLO)]},
)

# accept/empty_file.zar: zero-byte file
gen(
    "accept/empty_file.zar",
    zarwoot.build(dirs=[], files=[("empty.txt", b"", False)], symlinks=[]),
    {"expected": [file_meta("empty.txt", b"")]},
)

# accept/zero_byte_middle_single_frame.zar: zero-byte member in the middle of a
# single contents frame does not require a dedicated empty frame.
gen(
    "accept/zero_byte_middle_single_frame.zar",
    zarwoot.build(
        dirs=[],
        files=[("first.bin", b"hello", False), ("empty.bin", b"", False), ("second.bin", b"world", False)],
        symlinks=[],
    ),
    {
        "expected": [
            file_meta("first.bin", b"hello"),
            file_meta("empty.bin", b""),
            file_meta("second.bin", b"world"),
        ]
    },
)

# accept/zero_byte_middle_multi_frame.zar: zero-byte member between two real
# contents frames does not require an empty frame of its own.
_manifest = zarwoot.encode_manifest(
    [],
    [
        archive_file_entry("first.bin", b"hello"),
        archive_file_entry("empty.bin", b""),
        archive_file_entry("second.bin", b"world"),
    ],
    [],
)
gen(
    "accept/zero_byte_middle_multi_frame.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), compress(b"hello") + compress(b"world")),
    {
        "expected": [
            file_meta("first.bin", b"hello"),
            file_meta("empty.bin", b""),
            file_meta("second.bin", b"world"),
        ]
    },
)

# accept/all_empty_files_one_empty_frame.zar: multiple zero-byte files still
# only need one empty contents frame.
gen(
    "accept/all_empty_files_one_empty_frame.zar",
    zarwoot.build(
        dirs=[],
        files=[("a.bin", b"", False), ("b.bin", b"", False), ("c.bin", b"", False)],
        symlinks=[],
    ),
    {
        "expected": [
            file_meta("a.bin", b""),
            file_meta("b.bin", b""),
            file_meta("c.bin", b""),
        ]
    },
)

# accept/manifest_skippable_frame.zar: manifest split across two frames with a
# skippable frame between them.
_manifest = zarwoot.encode_manifest([], [archive_file_entry("hello.txt", HELLO)], [])
_mid = len(_manifest) // 2
_skippable = ZstdSkippableFrame(data=b"manifest-smuggled").pack()
gen(
    "accept/manifest_skippable_frame.zar",
    zarwoot.assemble(
        zarwoot.compress_single(_manifest[:_mid]) + _skippable + zarwoot.compress_single(_manifest[_mid:]),
        zarwoot.compress_single(HELLO),
    ),
    {"expected": [file_meta("hello.txt", HELLO)]},
)

# accept/contents_skippable_between_frames.zar: skippable frame between two
# real contents frames is ignored.
_manifest = zarwoot.encode_manifest(
    [],
    [
        archive_file_entry("first.bin", b"hello"),
        archive_file_entry("second.bin", b"world"),
    ],
    [],
)
gen(
    "accept/contents_skippable_between_frames.zar",
    zarwoot.assemble(
        zarwoot.compress_single(_manifest),
        compress(b"hello") + ZstdSkippableFrame(data=b"smuggled").pack() + compress(b"world"),
    ),
    {
        "expected": [
            file_meta("first.bin", b"hello"),
            file_meta("second.bin", b"world"),
        ]
    },
)

# accept/with_dir.zar: directory containing a file
gen(
    "accept/with_dir.zar",
    zarwoot.build(
        dirs=["sub"],
        files=[("sub/hello.txt", HELLO, False)],
        symlinks=[],
    ),
    {"expected": [dir_meta("sub"), file_meta("sub/hello.txt", HELLO)]},
)

# accept/executable.zar: file with the execute bit set
gen(
    "accept/executable.zar",
    zarwoot.build(dirs=[], files=[("run.sh", b"#!/bin/sh\n", True)], symlinks=[]),
    {"expected": [file_meta("run.sh", b"#!/bin/sh\n", executable=True)]},
)

# accept/nested_dirs.zar: parents listed before children
gen(
    "accept/nested_dirs.zar",
    zarwoot.build(
        dirs=["a", "a/b"],
        files=[("a/b/deep.txt", HELLO, False)],
        symlinks=[],
    ),
    {"expected": [dir_meta("a"), dir_meta("a/b"), file_meta("a/b/deep.txt", HELLO)]},
)

# accept/empty_dir.zar: archive containing only an empty directory
gen(
    "accept/empty_dir.zar",
    zarwoot.build(dirs=["emptydir"], files=[], symlinks=[]),
    {"expected": [dir_meta("emptydir")]},
)

# accept/with_symlink.zar: symlink whose target is a file in the archive
gen(
    "accept/with_symlink.zar",
    zarwoot.build(
        dirs=[],
        files=[("hello.txt", HELLO, False)],
        symlinks=[("link.txt", "hello.txt")],
    ),
    {"expected": [file_meta("hello.txt", HELLO), symlink_meta("link.txt", "hello.txt")]},
)

# accept/symlink_to_dir.zar: symlink whose target is a directory in the archive
gen(
    "accept/symlink_to_dir.zar",
    zarwoot.build(
        dirs=["subdir"],
        files=[("subdir/hello.txt", HELLO, False)],
        symlinks=[("link", "subdir")],
    ),
    {
        "expected": [
            dir_meta("subdir"),
            file_meta("subdir/hello.txt", HELLO),
            symlink_meta("link", "subdir"),
        ]
    },
)

# accept/nfkc_no_collision.zar: two files whose names are NFKC-equivalent but
# not identical under the normalization checks we apply here.  No common
# filesystem normalises to NFKC, so these are legitimately distinct names that
# must be accepted.
# U+00B2 (SUPERSCRIPT TWO, ²): NFKC → "2", NFC → "²", casefold → "²".
# "²file.txt" and "2file.txt" differ under NFC and casefold but collide under
# NFKC -- a check that should NOT be applied.
_sq2 = "²file.txt"   # ²file.txt
_dig = "2file.txt"
assert unicodedata.normalize("NFKC", _sq2) == unicodedata.normalize("NFKC", _dig)
assert unicodedata.normalize("NFC",  _sq2) != unicodedata.normalize("NFC",  _dig)
assert _sq2.casefold() != _dig.casefold()
_manifest = zarwoot.encode_manifest(
    [],
    [archive_file_entry(_sq2, b"hello"), archive_file_entry(_dig, b"world")],
    [],
)
gen(
    "accept/nfkc_no_collision.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), zarwoot.compress_single(b"helloworld")),
    {
        "expected": [
            file_meta(_sq2, b"hello"),
            file_meta(_dig, b"world"),
        ]
    },
)

# accept/nonbmp_filename.zar: file whose name contains a non-BMP emoji (U+1F600
# GRINNING FACE, encoded as the 4-byte UTF-8 sequence f0 9f 98 80).
# Non-BMP characters are valid in path strings and must be accepted.
_emoji_name = "\U0001F600.txt"  # GRINNING FACE
gen(
    "accept/nonbmp_filename.zar",
    zarwoot.build(dirs=[], files=[(_emoji_name, HELLO, False)], symlinks=[]),
    {"expected": [file_meta(_emoji_name, HELLO)]},
)

# accept/pua_filename.zar: file whose name contains a BMP private-use character
# (U+E000, the first code point in the BMP private-use area).
# Private-use code points are explicitly permitted.
_pua_name = "\ue000file.txt"
gen(
    "accept/pua_filename.zar",
    zarwoot.build(dirs=[], files=[(_pua_name, HELLO, False)], symlinks=[]),
    {"expected": [file_meta(_pua_name, HELLO)]},
)

# accept/no_files_no_contents.zar: archive with no files and a completely empty
# contents section (contents_csize=0, zero bytes, no frames at all).
# Demonstrates that a frame header is not required when there is nothing to store.
gen(
    "accept/no_files_no_contents.zar",
    zarwoot.assemble(zarwoot.compress_single(zarwoot.encode_manifest([], [], [])), b""),
    {"expected": []},
)

# ── iffy ──────────────────────────────────────────────────────────────────────

# iffy/default_ignorable.zar: two files whose names differ only by a
# Default-Ignorable code point (U+200D, ZWJ), which Linux ext4 casefold mode
# strips when comparing names.  The names are NFC-normalized and not case
# collisions, but they would collide on any filesystem that applies NFDICF.
# Security-focused decoders should reject this; permissive decoders may accept.
_di_a = "fi\u200dle.txt"  # ZWJ (U+200D) between 'i' and 'l'
_di_b = "file.txt"
assert unicodedata.normalize("NFC", _di_a) == _di_a   # already NFC
assert _di_a.casefold() != _di_b.casefold()           # not a casefold collision
_di_manifest = zarwoot.encode_manifest(
    [],
    [archive_file_entry(_di_a, b"hello"), archive_file_entry(_di_b, b"world")],
    [],
)
gen(
    "iffy/default_ignorable.zar",
    zarwoot.assemble(zarwoot.compress_single(_di_manifest), zarwoot.compress_single(b"helloworld")),
)

# ── reject ────────────────────────────────────────────────────────────────────

# Build a canonical valid archive to extract compressed streams from.
_valid = zarwoot.build(dirs=[], files=[("hello.txt", HELLO, False)], symlinks=[])
_m_size = struct.unpack_from("<Q", _valid, 8)[0]
_cm_valid = _valid[zarwoot.HEADER_SIZE : zarwoot.HEADER_SIZE + _m_size]
_cc_valid = _valid[zarwoot.HEADER_SIZE + _m_size + len(zarwoot.PADDING) :]

# reject/bad_magic.zar
gen("reject/bad_magic.zar", zarwoot.assemble(_cm_valid, _cc_valid, magic=b"XXXX"))

# reject/bad_compression.zar
gen("reject/bad_compression.zar", zarwoot.assemble(_cm_valid, _cc_valid, compression_field=b"gzip"))

# reject/bad_manifest_checksum.zar: checksum field is all zeros
gen("reject/bad_manifest_checksum.zar", zarwoot.assemble(_cm_valid, _cc_valid, manifest_checksum=bytes(32)))

# reject/bad_contents_checksum.zar: checksum field is all zeros
gen("reject/bad_contents_checksum.zar", zarwoot.assemble(_cm_valid, _cc_valid, contents_checksum=bytes(32)))

# reject/wrong_total_size.zar: header claims contents is 1 byte larger than it is
gen(
    "reject/wrong_total_size.zar",
    zarwoot.assemble(_cm_valid, _cc_valid, contents_size=len(_cc_valid) + 1),
)

# reject/truncated.zar: file ends mid-header
gen("reject/truncated.zar", _valid[:40])

# reject/bad_padding.zar: padding bytes are not ff ff ff ff
gen(
    "reject/bad_padding.zar",
    zarwoot.assemble(_cm_valid, _cc_valid, padding=b"\x00\x00\x00\x00"),
)

# reject/trailing_bytes.zar: valid archive with an extra byte appended.
# The size mismatch makes the total file length disagree with header fields.
gen("reject/trailing_bytes.zar", _valid + b"\x00")


# Path violations — inject invalid names directly into manifest dicts.
def _reject_path(path: str) -> bytes:
    file_entries = [archive_file_entry(path, HELLO)]
    manifest = zarwoot.encode_manifest([], file_entries, [])
    cm = zarwoot.compress_single(manifest)
    cc = zarwoot.compress_single(HELLO)
    return zarwoot.assemble(cm, cc)


# iffy/nfd_path.zar: a single file whose name is decomposed.
# Tests the normalization check in isolation -- no collision partner needed.
gen("iffy/nfd_path.zar", _reject_path(unicodedata.normalize("NFD", "café.txt")))

# iffy/greek_ypogegrammeni.zar: a single file whose name uses the Greek
# alpha-with-ypogegrammeni and acute example from weird-unicode.md.
# This exercises a second normalization edge case in the same iffy bucket.
gen(
    "iffy/greek_ypogegrammeni.zar",
    _reject_path(unicodedata.normalize("NFD", "\u1fb3\u0301.txt")),
)

# iffy/combining_order.zar: two filenames that differ only in the order of
# combining marks (i+U+0307+U+0323 vs i+U+0323+U+0307).  Both are not in
# canonical combining order individually (U+0323 CCC=220 must precede
# U+0307 CCC=230, and the pair composes further to U+1ECB+U+0307).  Their
# normalized forms are identical, so a validator must normalize before
# checking for duplicates -- not just compare raw casefolds.  This exercises
# the normalize→casefold→normalize pipeline.
_s1 = "ị̇"  # i + dot-above (U+0307, CCC 230) + dot-below (U+0323, CCC 220): wrong order
_s2 = "ị̇"  # i + dot-below (U+0323, CCC 220) + dot-above (U+0307, CCC 230): right order, but i+U+0323 composes
assert unicodedata.normalize("NFC", _s1) == unicodedata.normalize("NFC", _s2)
_manifest = zarwoot.encode_manifest(
    [], [archive_file_entry(_s1, b"hello"), archive_file_entry(_s2, b"hello")], []
)
gen(
    "iffy/combining_order.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), zarwoot.compress_single(b"hellohello")),
)

gen("reject/path_traversal.zar",   _reject_path("../../etc/passwd"))
gen("reject/absolute_path.zar",    _reject_path("/etc/passwd"))
gen("reject/backslash_path.zar",   _reject_path("dir\\file.txt"))
gen("reject/colon_path.zar",       _reject_path("d:windows"))
gen("reject/tilde_path.zar",       _reject_path("~/.bashrc"))
gen("reject/dot_component.zar",    _reject_path("foo/./bar.txt"))
gen("reject/dotdot_component.zar", _reject_path("foo/../bar.txt"))
gen("reject/empty_component.zar",  _reject_path("foo//bar.txt"))
gen("reject/trailing_dot.zar",     _reject_path("foo."))
gen("reject/trailing_space.zar",   _reject_path("foo "))
gen("reject/dot_name.zar",         _reject_path("."))
gen("reject/dotdot_name.zar",      _reject_path(".."))

# reject/bom_in_path.zar: path contains U+FEFF (BOM) in the middle.
gen("reject/bom_in_path.zar",      _reject_path("file\ufeffname.txt"))

# reject/noncharacter_path.zar: path contains U+FFFE, a Unicode non-character
# (not to be confused with U+FEFF BOM).
gen("reject/noncharacter_path.zar", _reject_path("file\ufffename.txt"))

# reject/surrogate_in_path.zar: path name contains a lone surrogate (U+D800).
# Surrogates cannot be encoded as UTF-8, so the JSON escape \ud800 is used to
# inject one.  The oracle must reject it after JSON parsing.
_surrogate_manifest = (
    b'[[],[{"name":"\\ud800file.txt","usize":5,"sha256":"'
    + sha256hex(HELLO).encode()
    + b'"}],[]]'
)
gen(
    "reject/surrogate_in_path.zar",
    zarwoot.assemble(zarwoot.compress_single(_surrogate_manifest), zarwoot.compress_single(HELLO)),
)

# reject/missing_sha256.zar: file metadata omits the new required hash field.
_manifest = zarwoot.encode_manifest([], [{"name": "hello.txt", "usize": 5}], [])
gen(
    "reject/missing_sha256.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), zarwoot.compress_single(HELLO)),
)

# reject/sha256_uppercase.zar: sha256 field uses uppercase hex, violating the
# "lowercase hex" requirement.  The oracle must reject it before content verification.
_manifest = zarwoot.encode_manifest(
    [],
    [{"name": "hello.txt", "usize": 5, "sha256": sha256hex(HELLO).upper()}],
    [],
)
gen(
    "reject/sha256_uppercase.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), zarwoot.compress_single(HELLO)),
)

# reject/sha256_wrong_length.zar: sha256 field is only 32 hex characters.
_manifest = zarwoot.encode_manifest(
    [],
    [{"name": "hello.txt", "usize": 5, "sha256": sha256hex(HELLO)[:32]}],
    [],
)
gen(
    "reject/sha256_wrong_length.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), zarwoot.compress_single(HELLO)),
)

# reject/bad_sha256.zar: file metadata includes a hash, but it does not match
# the extracted file contents.
_manifest = zarwoot.encode_manifest(
    [],
    [{"name": "hello.txt", "usize": 5, "sha256": "0" * 64}],
    [],
)
gen(
    "reject/bad_sha256.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), zarwoot.compress_single(HELLO)),
)

# reject/x_not_true.zar: 'x' field is present but set to false instead of true.
_manifest = zarwoot.encode_manifest(
    [],
    [{"name": "hello.txt", "usize": 5, "sha256": sha256hex(HELLO), "x": False}],
    [],
)
gen(
    "reject/x_not_true.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), zarwoot.compress_single(HELLO)),
)

# reject/unknown_field_in_file.zar: file entry contains an unrecognized field.
_manifest = zarwoot.encode_manifest(
    [],
    [{"name": "hello.txt", "usize": 5, "sha256": sha256hex(HELLO), "extra": "value"}],
    [],
)
gen(
    "reject/unknown_field_in_file.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), zarwoot.compress_single(HELLO)),
)

# reject/unknown_field_in_dir.zar: directory entry contains an unrecognized field.
_manifest = zarwoot.encode_manifest(
    [{"name": "subdir", "mode": "0755"}],
    [archive_file_entry("subdir/hello.txt", HELLO)],
    [],
)
gen(
    "reject/unknown_field_in_dir.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), zarwoot.compress_single(HELLO)),
)

# reject/file_split_across_frames.zar: one logical file is split across two
# contents frames, so the second frame begins in the middle of the file.
_manifest = zarwoot.encode_manifest(
    [],
    [{"name": "hello.txt", "usize": 5, "sha256": sha256hex(HELLO)}],
    [],
)
gen(
    "reject/file_split_across_frames.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), compress(b"hel") + compress(b"lo")),
)

# reject/duplicate_name_files.zar: same path twice in the files list
_manifest = zarwoot.encode_manifest(
    [],
    [archive_file_entry("same.txt", b"hello"), archive_file_entry("same.txt", b" world!")],
    [],
)
gen(
    "reject/duplicate_name_files.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), zarwoot.compress_single(b"hello world!")),
)

# reject/duplicate_name_dirs.zar: same path twice in the dirs list
_manifest = zarwoot.encode_manifest(
    [{"name": "dupdir"}, {"name": "dupdir"}],
    [],
    [],
)
gen(
    "reject/duplicate_name_dirs.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), zarwoot.compress_single(b"")),
)

# reject/duplicate_name_cross_section.zar: same path in dirs and files
_manifest = zarwoot.encode_manifest(
    [{"name": "foo"}],
    [archive_file_entry("foo", HELLO)],
    [],
)
gen(
    "reject/duplicate_name_cross_section.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), zarwoot.compress_single(HELLO)),
)

# reject/duplicate_name_file_symlink.zar: same path in files and symlinks
_manifest = zarwoot.encode_manifest(
    [],
    [archive_file_entry("same.txt", HELLO)],
    [{"name": "same.txt", "target": "hello.txt"}],
)
gen(
    "reject/duplicate_name_file_symlink.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), zarwoot.compress_single(HELLO)),
)

# reject/duplicate_name_dir_symlink.zar: same path in dirs and symlinks
_manifest = zarwoot.encode_manifest(
    [{"name": "same-dir"}],
    [],
    [{"name": "same-dir", "target": "hello.txt"}],
)
gen(
    "reject/duplicate_name_dir_symlink.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), zarwoot.compress_single(b"")),
)

# reject/duplicate_name_symlinks.zar: same path twice in the symlinks list
_manifest = zarwoot.encode_manifest(
    [],
    [archive_file_entry("hello.txt", HELLO)],
    [{"name": "same-link", "target": "hello.txt"}, {"name": "same-link", "target": "hello.txt"}],
)
gen(
    "reject/duplicate_name_symlinks.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), zarwoot.compress_single(HELLO)),
)

# iffy/case_collision.zar: "Foo.txt" and "foo.txt" collide under casefold
_manifest = zarwoot.encode_manifest(
    [],
    [archive_file_entry("Foo.txt", b"hello"), archive_file_entry("foo.txt", b"hello")],
    [],
)
gen(
    "iffy/case_collision.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), zarwoot.compress_single(b"hellohello")),
)

# reject/dir_missing.zar: file path references a directory not in dirs list
_manifest = zarwoot.encode_manifest([], [archive_file_entry("subdir/hello.txt", HELLO)], [])
gen(
    "reject/dir_missing.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), zarwoot.compress_single(HELLO)),
)

# reject/usize_mismatch.zar: manifest claims 999 bytes but stream only has 5
_manifest = zarwoot.encode_manifest([], [archive_file_entry("hello.txt", HELLO, usize=999)], [])
gen(
    "reject/usize_mismatch.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), zarwoot.compress_single(HELLO)),
)

# accept/manifest_multi_frame.zar: manifest stream contains two zstd frames
_manifest = zarwoot.encode_manifest([], [archive_file_entry("hello.txt", HELLO)], [])
_mid = len(_manifest) // 2
_multi_cm = zarwoot.compress_single(_manifest[:_mid]) + zarwoot.compress_single(_manifest[_mid:])
gen("accept/manifest_multi_frame.zar", zarwoot.assemble(_multi_cm, _cc_valid))

# reject/symlink_unknown_target.zar: target not present in dirs or files
_manifest = zarwoot.encode_manifest([], [], [{"name": "link.txt", "target": "nonexistent.txt"}])
gen(
    "reject/symlink_unknown_target.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), zarwoot.compress_single(b"")),
)

# reject/symlink_to_symlink.zar: link2 targets link1 which is a symlink, not a file/dir
_manifest = zarwoot.encode_manifest(
    [],
    [archive_file_entry("hello.txt", HELLO)],
    [{"name": "link1.txt", "target": "hello.txt"}, {"name": "link2.txt", "target": "link1.txt"}],
)
gen(
    "reject/symlink_to_symlink.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), zarwoot.compress_single(HELLO)),
)

# reject/window_too_large.zar: contents is a single-segment zstd frame whose
# Window_Size = Frame_Content_Size = 1 GB (SSF=1).  The "zstd" compression
# identifier mandates Window_Size <= 8 MB.  The compressed output is ~2 KB
# (one RLE block per 2 MB of zeros); the oracle rejects at frame-header
# inspection before verifying content hashes, so the sha256 is a dummy.
_ONE_GB = 1 << 30
_big_frame = make_zstd_single_segment_rle(0, _ONE_GB)
_big_manifest = zarwoot.encode_manifest(
    [], [{"name": "big.bin", "usize": _ONE_GB, "sha256": "0" * 64}], []
)
gen(
    "reject/window_too_large.zar",
    zarwoot.assemble(zarwoot.compress_single(_big_manifest), _big_frame),
)

# reject/frame_start_on_first_file.zar: first file has frame_start set, which
# is always forbidden (the first file is implicitly at offset 0).
_file_entry = {**archive_file_entry("hello.txt", HELLO), "frame_start": 0}
_manifest = zarwoot.encode_manifest([], [_file_entry], [])
gen(
    "reject/frame_start_on_first_file.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), zarwoot.compress_single(HELLO)),
)

# reject/frame_start_after_zero_byte.zar: a file immediately following a
# zero-byte file carries frame_start, which is MUST NOT per spec.  The
# zero-byte file advances the uncompressed position by nothing, making any
# declared frame boundary here indistinguishable from one on the zero-byte
# file itself and therefore an illegal duplicate.
_frame_a = compress(b"hello")
_frame_b = compress(b"world")
_manifest = zarwoot.encode_manifest(
    [],
    [
        archive_file_entry("a.txt", b"hello"),
        archive_file_entry("empty.txt", b""),
        {**archive_file_entry("b.txt", b"world"), "frame_start": len(_frame_a)},
    ],
    [],
)
gen(
    "reject/frame_start_after_zero_byte.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), _frame_a + _frame_b),
)

# reject/frame_start_off_by_one.zar: frame_start points one byte past the
# actual start of the second contents frame.  Should fail even if the bytes at
# the declared position resemble a frame header.
_frame1 = compress(b"hello")
_frame2 = compress(b"world")
_manifest = zarwoot.encode_manifest(
    [],
    [
        archive_file_entry("a.txt", b"hello"),
        {**archive_file_entry("b.txt", b"world"), "frame_start": len(_frame1) + 1},
    ],
    [],
)
gen(
    "reject/frame_start_off_by_one.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), _frame1 + _frame2),
)

# reject/frame_start_not_increasing.zar: two files both declare frame_start,
# but the second value equals the first (not strictly increasing).
_frame1 = compress(b"hello")
_frame2 = compress(b"world")
_manifest = zarwoot.encode_manifest(
    [],
    [
        archive_file_entry("a.txt", b"hello"),
        {**archive_file_entry("b.txt", b"world"), "frame_start": len(_frame1)},
        {**archive_file_entry("c.txt", b"world"), "frame_start": len(_frame1)},  # duplicate
    ],
    [],
)
gen(
    "reject/frame_start_not_increasing.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), _frame1 + _frame2 + _frame2),
)

# reject/frame_start_at_csize.zar: frame_start on the last file equals
# contents_csize exactly, pointing one past the end where no frame can start.
# Uses a zero-byte last file so the contents section has exactly one frame
# (for a.txt), making frame_start == csize unambiguous.
_frame = compress(b"hello")
_manifest = zarwoot.encode_manifest(
    [],
    [
        archive_file_entry("a.txt", b"hello"),
        {**archive_file_entry("b.txt", b""), "frame_start": len(_frame)},
    ],
    [],
)
gen(
    "reject/frame_start_at_csize.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), _frame),
)

# reject/frame_start_beyond_csize.zar: frame_start value is larger than
# contents_csize, so no frame can possibly start there.
_frame1 = compress(b"hello")
_frame2 = compress(b"world")
_manifest = zarwoot.encode_manifest(
    [],
    [
        archive_file_entry("a.txt", b"hello"),
        {**archive_file_entry("b.txt", b"world"), "frame_start": len(_frame1) + len(_frame2) + 100},
    ],
    [],
)
gen(
    "reject/frame_start_beyond_csize.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), _frame1 + _frame2),
)

# reject/frame_start_at_fake_magic.zar: frame_start points at zstd magic bytes
# that are embedded inside a raw-block frame's content, not at a real frame
# boundary.  Tests that the oracle is cursor-driven and cannot be tricked by
# embedded magic bytes.
#
# A raw-block zstd frame (Single_Segment, no compression) stores its payload
# verbatim after the 9-byte header (4 magic + 1 FHD + 1 FCS + 3 block_header).
# If the payload starts with the zstd magic bytes, they appear at cpos=9.
# A magic-scanning oracle would misidentify cpos=9 as a frame start.
_fake_magic_payload = b"\x28\xb5\x2f\xfd hello"  # fake magic at the start
# Build a raw-block single-segment frame by hand:
#   FHD=0x20 → SSF=1, FCS_flag=0 (1-byte FCS for content < 256 bytes)
#   block header: Last=1, Type=00 (raw), Size=N → (N<<3)|1
_rn = len(_fake_magic_payload)
_raw_frame = (
    b"\x28\xb5\x2f\xfd"                  # frame magic
    + b"\x20"                             # FHD
    + bytes([_rn])                        # 1-byte FCS
    + struct.pack("<I", (_rn << 3) | 1)[:3]  # block header
    + _fake_magic_payload
)
_FAKE_MAGIC_OFFSET = 9  # byte offset within contents where fake magic appears
_real_second_frame = compress(b"world")
_manifest = zarwoot.encode_manifest(
    [],
    [
        archive_file_entry("a.txt", _fake_magic_payload),
        {**archive_file_entry("b.txt", b"world"), "frame_start": _FAKE_MAGIC_OFFSET},
    ],
    [],
)
gen(
    "reject/frame_start_at_fake_magic.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), _raw_frame + _real_second_frame),
)

# reject/dirs_out_of_order.zar: child directory listed before its parent.
_manifest = zarwoot.encode_manifest(
    [{"name": "a/b"}, {"name": "a"}],
    [archive_file_entry("a/b/hello.txt", HELLO)],
    [],
)
gen(
    "reject/dirs_out_of_order.zar",
    zarwoot.assemble(zarwoot.compress_single(_manifest), zarwoot.compress_single(HELLO)),
)

# reject/contents_frame_history_bleed.zar: the second content frame was
# compressed with the first frame's payload as a raw prefix. A decoder that
# incorrectly carries history across frame boundaries may accept it, but ZAR
# contents are frame-independent.
_history_prefix = b"abcdefghijklmnop" * 10  # 160 bytes
_history_suffix = b"abcdefghijklmnop" * 3  # 48 bytes
_manifest = zarwoot.encode_manifest(
    [],
    [
        archive_file_entry("prefix.bin", _history_prefix),
        archive_file_entry("suffix.bin", _history_suffix),
    ],
    [],
)
gen(
    "reject/contents_frame_history_bleed.zar",
    zarwoot.assemble(
        zarwoot.compress_single(_manifest),
        compress(_history_prefix) + compress_with_prefix(_history_suffix, _history_prefix),
    ),
)

# accept/contents_skippable_frame.zar: a skippable frame is smuggled into the
# contents stream between two real frames. RFC 8878 says decoders skip these,
# and ZAR now permits that.
_manifest = zarwoot.encode_manifest(
    [],
    [
        archive_file_entry("first.bin", b"hello"),
        archive_file_entry("second.bin", b"world"),
    ],
    [],
)
gen(
    "accept/contents_skippable_frame.zar",
    zarwoot.assemble(
        zarwoot.compress_single(_manifest),
        compress(b"hello") + ZstdSkippableFrame(data=b"smuggled").pack() + compress(b"world"),
    ),
)

# ── malicious ─────────────────────────────────────────────────────────────────

# malicious/nfc_nfd_collision.zar: two file entries whose names are the same
# after canonical normalization.  Both pass UTF-8 validation and neither path
# component ends in a dot/space, but they collide after normalization.
# A strict decoder must normalize and reject; a lax one may extract both,
# with the second overwriting the first on any filesystem that normalizes
# names before comparison.
_nfc = unicodedata.normalize("NFC", "café.txt")  # precomposed form
_nfd = unicodedata.normalize("NFD", "café.txt")  # decomposed form
assert _nfc != _nfd
_manifest = zarwoot.encode_manifest(
    [],
    [archive_file_entry(_nfc, b"hello"), archive_file_entry(_nfd, b" world!")],
    [],
)
gen(
    "malicious/nfc_nfd_collision.zar",
    zarwoot.assemble(
        zarwoot.compress_single(_manifest),
        zarwoot.compress_single(b"hello world!"),
    ),
    {"vulnerable_when": [{"member": _nfd}]},
)
