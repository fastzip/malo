import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_src"))

import hashlib
import struct

from malo.nar.construct import s, nar, regular, directory, directory_raw, symlink


for _d in ("accept", "iffy", "reject", "malicious"):
    Path(_d).mkdir(exist_ok=True)


def gen(filename: str, data: bytes, meta: dict | None = None) -> None:
    Path(filename).write_bytes(data)
    meta_path = Path(filename).with_suffix(".json")
    if meta is not None:
        meta_path.write_text(json.dumps(meta, separators=(", ", ": ")) + "\n")
    elif meta_path.exists():
        meta_path.unlink()


def _extra_root_bytes(root1: bytes, root2: bytes) -> bytes:
    """Two complete NAR archives concatenated back-to-back."""
    return nar(root1) + nar(root2)


# ── accept ────────────────────────────────────────────────────────────────────

# accept/empty_file.nar: root is a single empty regular file
gen(
    "accept/empty_file.nar",
    nar(regular(b"")),
)

# accept/empty_dir.nar: root is an empty directory
gen(
    "accept/empty_dir.nar",
    nar(directory([])),
)

# accept/dir_one_file.nar: directory containing one regular file
gen(
    "accept/dir_one_file.nar",
    nar(directory([
        ("hello.txt", regular(b"Hello, NAR!\n")),
    ])),
)

# accept/dir_two_files.nar: directory with two files in correct lexicographic order
gen(
    "accept/dir_two_files.nar",
    nar(directory([
        ("a.txt", regular(b"aaa\n")),
        ("b.txt", regular(b"bbb\n")),
    ])),
)

# accept/symlink.nar: root is a symlink (no target file is present in the archive)
gen(
    "accept/symlink.nar",
    nar(symlink("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example")),
)

# accept/executable.nar: directory with one executable regular file
gen(
    "accept/executable.nar",
    nar(directory([
        ("run.sh", regular(b"#!/bin/sh\necho hello\n", executable=True)),
    ])),
)

# ── reject ────────────────────────────────────────────────────────────────────

# reject/dir_two_files_wrong_order.nar: b.txt appears before a.txt; the NAR
# spec requires directory entries to be in strict lexicographic order.
gen(
    "reject/dir_two_files_wrong_order.nar",
    nar(directory_raw([
        ("b.txt", regular(b"bbb\n")),
        ("a.txt", regular(b"aaa\n")),
    ])),
)

# reject/dir_two_files_same_name.nar: two entries both named "file.txt"
gen(
    "reject/dir_two_files_same_name.nar",
    nar(directory_raw([
        ("file.txt", regular(b"first\n")),
        ("file.txt", regular(b"second\n")),
    ])),
)

# reject/file_and_dir_same_name.nar: entry "foo" appears as both a regular file
# and a directory (same name used twice, different types)
gen(
    "reject/file_and_dir_same_name.nar",
    nar(directory_raw([
        ("foo", regular(b"content\n")),
        ("foo", directory([])),
    ])),
)

# reject/two_root_dirs.nar: a complete directory root followed immediately by
# another complete directory root.  A correct parser must stop after the first
# archive and reject the trailing second root node.
gen(
    "reject/two_root_dirs.nar",
    _extra_root_bytes(
        directory([("a", regular(b"first\n"))]),
        directory([("b", regular(b"second\n"))]),
    ),
    meta={
        "vulnerable_when": [{"member": "b"}],
    },
)

# reject/two_root_files.nar: a complete regular-file root followed immediately
# by another regular-file root.  Like two_root_dirs.nar, this is an extra
# sequential root node after the archive should already have ended.
gen(
    "reject/two_root_files.nar",
    _extra_root_bytes(
        regular(b"first\n"),
        regular(b"second\n"),
    ),
)

# reject/file_then_symlink_root.nar: a complete regular-file root followed by a
# complete symlink root.  Distinct root-node types ensure the parser does not
# accidentally treat the trailing bytes as a valid continuation.
gen(
    "reject/file_then_symlink_root.nar",
    _extra_root_bytes(
        regular(b"first\n"),
        symlink("b"),
    ),
)

# reject/executable_before_type.nar: "executable" token precedes the "type"
# declaration in a regular file node, violating required field order.
# A correct NAR parser must see "type" as the very first token inside "(".
gen(
    "reject/executable_before_type.nar",
    nar(
        s("(")
        + s("executable") + s("")      # executable comes before type — invalid
        + s("type") + s("regular")
        + s("contents") + s(b"hello")
        + s(")")
    ),
)

# ── iffy ─────────────────────────────────────────────────────────────────────

# iffy/executable_twice.nar: "executable" marker appears twice before "contents".
# The spec only allows it once; some parsers may accept and ignore the duplicate.
gen(
    "iffy/executable_twice.nar",
    nar(
        s("(")
        + s("type") + s("regular")
        + s("executable") + s("")   # first executable marker
        + s("executable") + s("")   # duplicate
        + s("contents") + s(b"hello")
        + s(")")
    ),
)

# iffy/unknown_tag.nar: an unrecognised token ("xattr") appears after "contents"
# but before the closing ")".  Strict parsers reject; lenient ones may skip it.
gen(
    "iffy/unknown_tag.nar",
    nar(
        s("(")
        + s("type") + s("regular")
        + s("contents") + s(b"hello")
        + s("xattr") + s(b"")   # unknown field
        + s(")")
    ),
)

# iffy/no_contents.nar: a regular file node with no "contents" field at all —
# just "(" "type" "regular" ")".  The spec requires contents; some parsers may
# silently emit an empty file.
gen(
    "iffy/no_contents.nar",
    nar(
        s("(")
        + s("type") + s("regular")
        + s(")")
    ),
)

# ── malicious ─────────────────────────────────────────────────────────────────

# malicious/symlink_then_file.nar: a directory contains "link" as a symlink to
# /etc/passwd, then immediately contains another entry also named "link" as a
# regular file.  A naive extractor that processes entries sequentially will:
#   (1) create link → /etc/passwd on disk, then
#   (2) open "link" to write the file payload — following the symlink and
#       writing "pwned\n" into /etc/passwd.
# The symlink target (/etc/passwd) is intentionally absent from this archive;
# only the symlink and the duplicate same-named file entry are present.
gen(
    "malicious/symlink_then_file.nar",
    nar(directory_raw([
        ("link", symlink("/etc/passwd")),
        ("link", regular(b"pwned\n")),
    ])),
)

gen(
    "malicious/symlink_local_then_file.nar",
    nar(directory_raw([
        ("link", symlink("a")),
        ("link", regular(b"pwned\n")),
    ])),
    meta={
        # Attack succeeds when extractor follows the symlink "link"→"a" and
        # writes the file payload through it, creating "a" in the same directory.
        "vulnerable_when": [{"member": "a"}],
    },
)

# reject/dir_two_dirs_same_name.nar: two directory entries both named "subdir"
gen(
    "reject/dir_two_dirs_same_name.nar",
    nar(directory_raw([
        ("subdir", directory([])),
        ("subdir", directory([("file.txt", regular(b"hello\n"))])),
    ])),
)

# malicious/dir_then_symlink_same_name.nar: a populated directory "output/" is
# followed by a symlink also named "output" pointing to "/etc".  A naive
# extractor first creates output/ and populates it, then replaces output with
# a symlink to /etc — so output/something subsequently resolves to /etc/something.
gen(
    "malicious/dir_then_symlink_same_name.nar",
    nar(directory_raw([
        ("output", directory([
            ("result.txt", regular(b"build output\n")),
        ])),
        ("output", symlink("/etc")),
    ])),
)

# ── malicious: path-component attacks ────────────────────────────────────────

# malicious/slash_begin_name.nar: entry name starts with "/" — an absolute path.
# A naive extractor might write outside the extraction root.
gen(
    "malicious/slash_begin_name.nar",
    nar(directory_raw([
        (b"/etc", regular(b"pwned\n")),
    ])),
)

# malicious/slash_middle_name.nar: entry name contains "/" in the middle.
# A naive extractor treats this as a path separator, writing to a subdirectory
# that was never explicitly declared as a directory entry.
gen(
    "malicious/slash_middle_name.nar",
    nar(directory_raw([
        (b"foo/bar", regular(b"pwned\n")),
    ])),
)

# malicious/slash_end_name.nar: entry name ends with "/".
# Some extractors may strip the trailing slash and create a file or directory
# with an otherwise-valid name; others may misparse the entry.
gen(
    "malicious/slash_end_name.nar",
    nar(directory_raw([
        (b"dir/", regular(b"pwned\n")),
    ])),
)

# malicious/dotdot_name.nar: entry named ".." — classic directory traversal.
# An extractor that resolves entry names against the extraction root will
# write outside it.
gen(
    "malicious/dotdot_name.nar",
    nar(directory_raw([
        (b"..", regular(b"pwned\n")),
    ])),
)

# malicious/nfc_nfd_collision.nar: a directory containing two entries whose
# names are visually identical ("é.txt") but encoded differently: one uses
# the precomposed NFC form (U+00E9, 2 UTF-8 bytes) and the other the
# decomposed NFD form (U+0065 U+0301, 3 UTF-8 bytes).  On Linux/ext4 (byte-
# comparison semantics) these are distinct; on macOS HFS+/APFS (which
# normalises filenames to NFD) extracting this NAR causes one entry to
# silently overwrite the other.
# NFD sorts before NFC (0x65 < 0xC3), so entries are in valid NAR order.
gen(
    "malicious/nfc_nfd_collision.nar",
    nar(directory_raw([
        ("é.txt", regular(b"nfd content\n")),    # NFD: e + combining acute
        ("é.txt",  regular(b"nfc content\n")),    # NFC: precomposed é
    ])),
)

# ── iffy: unusual but syntactically valid entry names ────────────────────────

# iffy/name_8_bytes.nar: entry name is exactly 8 bytes, so the NAR string token
# has zero padding bytes after the data.  A buggy encoder computing
# (8 - n%8) instead of (8 - n%8)%8 would emit 8 extra null bytes; a buggy
# decoder may then read 8 bytes too many before the next token.
gen(
    "iffy/name_8_bytes.nar",
    nar(directory([
        (b"data.txt", regular(b"content\n")),
    ])),
)

# iffy/name_leading_space.nar: entry name begins with a space.  POSIX allows
# spaces in filenames; shell tools and some extractors may mishandle them.
gen(
    "iffy/name_leading_space.nar",
    nar(directory([
        (b" foo.txt", regular(b"content\n")),
    ])),
)

# iffy/name_trailing_space.nar: entry name ends with a space.
gen(
    "iffy/name_trailing_space.nar",
    nar(directory([
        (b"foo .txt", regular(b"content\n")),
    ])),
)

# iffy/name_backslash_begin.nar: entry name starts with a backslash.
# Valid on POSIX; treated as an escape character or path separator on Windows.
gen(
    "iffy/name_backslash_begin.nar",
    nar(directory([
        (b"\\foo", regular(b"content\n")),
    ])),
)

# iffy/name_backslash_middle.nar: backslash in the middle of an entry name.
gen(
    "iffy/name_backslash_middle.nar",
    nar(directory([
        (b"foo\\bar", regular(b"content\n")),
    ])),
)

# iffy/name_backslash_end.nar: entry name ends with a backslash.
gen(
    "iffy/name_backslash_end.nar",
    nar(directory([
        (b"foo\\", regular(b"content\n")),
    ])),
)

# iffy/name_colon_begin.nar: entry name starts with a colon.
# Valid on POSIX; Windows treats "X:" as a drive specifier and "::$DATA" as
# an alternate data stream.
gen(
    "iffy/name_colon_begin.nar",
    nar(directory([
        (b":foo", regular(b"content\n")),
    ])),
)

# iffy/name_colon_middle.nar: colon in the middle of an entry name.
gen(
    "iffy/name_colon_middle.nar",
    nar(directory([
        (b"foo:bar", regular(b"content\n")),
    ])),
)

# iffy/name_colon_end.nar: entry name ends with a colon.
gen(
    "iffy/name_colon_end.nar",
    nar(directory([
        (b"foo:", regular(b"content\n")),
    ])),
)

# iffy/name_latin1.nar: entry name contains the byte 0xE9 (Latin-1 'é'), which
# is not valid UTF-8.  The NAR spec does not mandate encoding; some parsers
# pass non-UTF-8 names through, others reject them.
gen(
    "iffy/name_latin1.nar",
    nar(directory([
        (b"caf\xe9.txt", regular(b"content\n")),
    ])),
)

# iffy/name_overlong_utf8.nar: entry name contains an overlong UTF-8 encoding.
# 0xC0 0xAF is a two-byte overlong encoding of U+002F ('/').  This is invalid
# UTF-8 per RFC 3629, but older decoders that don't check for overlong forms
# may decode it as '/', enabling a directory-traversal attack.
gen(
    "iffy/name_overlong_utf8.nar",
    nar(directory([
        (b"foo\xc0\xafbar", regular(b"content\n")),
    ])),
)

# iffy/name_32k.nar: entry name is 32 768 bytes long (all ASCII 'a').  This
# probes parsers that use a static char buffer of PATH_MAX (4096) or NAME_MAX
# (255) for path assembly or validation.
gen(
    "iffy/name_32k.nar",
    nar(directory([
        (b"a" * 32768, regular(b"content\n")),
    ])),
)

# iffy/name_nfc.nar: entry name is "é.txt" in NFC (precomposed, U+00E9 → 2 bytes).
gen(
    "iffy/name_nfc.nar",
    nar(directory([
        ("é.txt", regular(b"nfc content\n")),
    ])),
)

# iffy/name_nfd.nar: entry name is "é.txt" in NFD (decomposed: U+0065 + U+0301 → 3 bytes).
# This and name_nfc.nar look identical when displayed but have different byte
# sequences.  On macOS HFS+/APFS, the kernel normalises filenames so both
# would map to the same inode.
gen(
    "iffy/name_nfd.nar",
    nar(directory([
        ("é.txt", regular(b"nfd content\n")),
    ])),
)

# ── reject: invalid entry names ───────────────────────────────────────────────

# reject/null_in_name.nar: entry name contains a null byte.  C-string APIs
# silently truncate at the null, so the parser sees a different (shorter) name
# than the one encoded in the NAR.  A correct parser must reject this.
gen(
    "reject/null_in_name.nar",
    nar(directory_raw([
        (b"foo\x00bar", regular(b"content\n")),
    ])),
    meta={
        "vulnerable_when_not": [{"member": "foo\x00bar"}],
    },
)

# ── reject: misordered fields ─────────────────────────────────────────────────

# reject/wrong_field_order.nar: a regular file node where the fields appear in
# completely wrong order: "contents" first, then "executable", then "type".
# A correct parser must see "type" as the very first field inside "(".
gen(
    "reject/wrong_field_order.nar",
    nar(
        s("(")
        + s("contents") + s(b"hello")   # contents before type — invalid
        + s("executable") + s("")
        + s("type") + s("regular")
        + s(")")
    ),
)

# reject/executable_after_contents.nar: "executable" appears after "contents".
# The spec requires executable to precede contents.
gen(
    "reject/executable_after_contents.nar",
    nar(
        s("(")
        + s("type") + s("regular")
        + s("contents") + s(b"hello")
        + s("executable") + s("")       # too late — must precede contents
        + s(")")
    ),
)

# ── iffy: BOM in filename ─────────────────────────────────────────────────────

# iffy/name_bom_start.nar: entry name begins with a UTF-8 BOM (U+FEFF).
# BOM is valid UTF-8 (3 bytes: 0xEF 0xBB 0xBF) but unusual as a filename
# prefix.  Some parsers normalise filenames by stripping leading BOMs, which
# would create a different file (named "file.txt") than what the NAR encoded.
gen(
    "iffy/name_bom_start.nar",
    nar(directory([
        ("﻿file.txt", regular(b"content\n")),
    ])),
    meta={
        "vulnerable_when_not": [{"member": "﻿file.txt"}],
    },
)

# iffy/name_bom_middle.nar: BOM appears in the middle of the filename.
gen(
    "iffy/name_bom_middle.nar",
    nar(directory([
        ("foo﻿bar.txt", regular(b"content\n")),
    ])),
    meta={
        "vulnerable_when_not": [{"member": "foo﻿bar.txt"}],
    },
)

# ── reject: truncated NAR ─────────────────────────────────────────────────────

# reject/truncated_in_content.nar: NAR that claims a 1024-byte regular file
# but provides only the first 8 bytes (the length field) before EOF.  A
# correct parser must detect the premature EOF and reject immediately.
_TRUNC_LEN = 1024
gen(
    "reject/truncated_in_content.nar",
    (
        s("nix-archive-1")
        + s("(")
        + s("type") + s("regular")
        + s("contents")
        + struct.pack("<Q", _TRUNC_LEN)   # claims 1024 bytes follow
        # payload intentionally omitted — fewer than 1024 bytes are available
    ),
)

# reject/truncated_in_magic.nar: file contains fewer bytes than the magic
# header, cutting off mid-length-prefix.
gen(
    "reject/truncated_in_magic.nar",
    b"\x0d\x00\x00\x00\x00\x00\x00\x00nix-arc",   # length 13, only 7 bytes
)

# ── reject: nonzero padding bytes ─────────────────────────────────────────────

def _s_bad_pad(data: bytes) -> bytes:
    """NAR string token with 0x41 fill instead of zero padding."""
    n = len(data)
    pad = (8 - n % 8) % 8
    return struct.pack("<Q", n) + data + b"\x41" * pad

# iffy/nonzero_padding.nar: a regular file node where the 3 padding bytes
# after the 5-byte "hello" contents are 0x41 ('A') instead of 0x00.
# The NAR spec requires padding to be zero; strict parsers reject this.
# Lenient parsers may silently accept, in which case they should still
# report the file with the correct content (sha256 of b"hello").
# vulnerable_when_not: member "." — fires if the oracle accepted but did not
# report the root member (e.g. the padding was misread as a token boundary).
gen(
    "iffy/nonzero_padding.nar",
    (
        s("nix-archive-1")
        + s("(")
        + s("type") + s("regular")
        + s("contents")
        + _s_bad_pad(b"hello")   # 3 bytes of 0x41 instead of 0x00
        + s(")")
    ),
    meta={
        "vulnerable_when_not": [{"member": "."}],
    },
)

# iffy/nonzero_padding_in_name.nar: the entry NAME token "foo" (3 bytes) has
# its 5 padding bytes set to 0x41 ('A') instead of 0x00.
# vulnerable_when: member "fooAAAAA" — the parser slurped padding bytes into
#   the name body and reported an 8-byte name.
# vulnerable_when_not: member "foo" — the parser accepted but the correctly-
#   named member is absent (the name was mangled in some other way).
gen(
    "iffy/nonzero_padding_in_name.nar",
    (
        s("nix-archive-1")
        + s("(") + s("type") + s("directory")
        + s("entry") + s("(")
        + s("name") + _s_bad_pad(b"foo")   # "foo" + 5 × 0x41 padding
        + s("node")
        + s("(") + s("type") + s("regular") + s("contents") + s(b"ok") + s(")")
        + s(")")                            # close entry
        + s(")")                            # close directory
    ),
    meta={
        "vulnerable_when": [{"member": "fooAAAAA"}],
        "vulnerable_when_not": [{"member": "foo"}],
    },
)

# ── reject: duplicate fields ──────────────────────────────────────────────────

# reject/contents_twice.nar: "contents" appears twice in a regular file node.
# The NAR spec does not permit duplicate fields; this must be rejected.
# vulnerable_when: member "." — fires if the oracle accepted (any acceptance
# is wrong, since the root "." always appears on successful parse).
gen(
    "reject/contents_twice.nar",
    nar(
        s("(")
        + s("type") + s("regular")
        + s("contents") + s(b"first\n")    # first
        + s("contents") + s(b"second\n")   # duplicate — must be rejected
        + s(")")
    ),
    meta={
        "vulnerable_when": [{"member": "."}],
    },
)

# ── iffy: Unicode surrogate code points in entry name ─────────────────────────

# iffy/name_surrogate_high.nar: entry name contains the WTF-8 encoding of a
# high surrogate (U+D800, bytes \xED\xA0\x80).  This is invalid UTF-8 per
# RFC 3629 (surrogates are disallowed) but accepted by some implementations
# that use WTF-8 or CESU-8.
gen(
    "iffy/name_surrogate_high.nar",
    nar(directory([
        (b"foo\xed\xa0\x80bar", regular(b"content\n")),
    ])),
)

# iffy/name_surrogate_low.nar: WTF-8 low surrogate (U+DC00, bytes \xED\xB0\x80).
gen(
    "iffy/name_surrogate_low.nar",
    nar(directory([
        (b"foo\xed\xb0\x80bar", regular(b"content\n")),
    ])),
)

# iffy/name_surrogate_pair.nar: a WTF-8 surrogate pair (\xED\xA0\x80\xED\xB0\x80,
# i.e. U+D800 U+DC00 which encodes U+10000 in UTF-16).  CESU-8 encoders produce
# this; a proper UTF-8 implementation would use the 4-byte form \xF0\x90\x80\x80.
gen(
    "iffy/name_surrogate_pair.nar",
    nar(directory([
        (b"foo\xed\xa0\x80\xed\xb0\x80bar", regular(b"content\n")),
    ])),
)

# ── malicious: dot and path-traversal via entry names ─────────────────────────

# malicious/dot_dir_traversal.nar: a directory containing an entry named "."
# (single dot).  A correct parser must reject this (dot is reserved), but a
# naive extractor that builds paths by string concatenation will compute
# base/"."/"payload.txt" = base/"payload.txt" — extracting the file directly
# into the extraction root instead of into a subdirectory.
# vulnerable_when: member "payload.txt" — the file was placed in the root
# rather than being rejected.
gen(
    "malicious/dot_dir_traversal.nar",
    nar(directory_raw([
        (b".", directory([
            ("payload.txt", regular(b"surprise\n")),
        ])),
    ])),
    meta={
        "vulnerable_when": [{"member": "payload.txt"}],
    },
)

# malicious/dot_nested_traversal.nar: two levels of "." subdirectories.
# base/"."/"."/"payload.txt" collapses to base/"payload.txt" on pathlib,
# confirming the entry escapes its declared nesting depth.
# vulnerable_when: member "payload.txt" — the two-level dot collapsed.
gen(
    "malicious/dot_nested_traversal.nar",
    nar(directory_raw([
        (b".", directory_raw([
            (b".", directory([
                ("payload.txt", regular(b"surprise\n")),
            ])),
        ])),
    ])),
    meta={
        "vulnerable_when": [{"member": "payload.txt"}],
    },
)

# malicious/slash_name_with_ext.nar: entry name "foo/bar.txt" — a slash in the
# middle of a name that includes an extension, testing that the extension is not
# used as a filename-detection bypass.
gen(
    "malicious/slash_name_with_ext.nar",
    nar(directory_raw([
        (b"foo/bar.txt", regular(b"pwned\n")),
    ])),
)

# ── reject: empty or null entry name ─────────────────────────────────────────

# reject/empty_name.nar: entry name is an empty string b"".  NAR requires entry
# names to be non-empty; an empty name has no meaningful filesystem equivalent
# and must be rejected by any correct parser.
gen(
    "reject/empty_name.nar",
    nar(directory_raw([
        (b"", regular(b"content\n")),
    ])),
)

# ── malicious: dotdot via path component ──────────────────────────────────────

# malicious/dotdot_path_component.nar: a directory contains a legitimate
# subdirectory "a" followed by an entry whose name is the raw string "a/../b" —
# a slash-containing name with an embedded dotdot component.  A correct parser
# rejects this because "/" is not permitted in an entry name.  A naive extractor
# that splits the name on "/" and resolves ".." will:
#   (1) descend into subdirectory "a" (already created as a real directory)
#   (2) ascend via ".." to the extraction root
#   (3) create "b" in the extraction root
# vulnerable_when: member "b" — the traversal was resolved and "b" landed at root.
gen(
    "malicious/dotdot_path_component.nar",
    nar(directory_raw([
        ("a", directory([
            ("x.txt", regular(b"innocent\n")),
        ])),
        (b"a/../b", regular(b"pwned\n")),
    ])),
    meta={
        "vulnerable_when": [{"member": "b"}],
    },
)

# malicious/symlink_dotdot_path_component.nar: like the previous case, but the
# path "a/.." is itself influenced by a symlink.  The archive contains a real
# directory tree at "b/c" and a symlink "a" -> "b/c".  A naive extractor that
# normalizes "a/../payload.txt" lexically may place the file at the root, while
# a filesystem-aware resolver can land it under "b/payload.txt".
gen(
    "malicious/symlink_dotdot_path_component.nar",
    nar(directory_raw([
        ("b", directory([
            ("c", directory([])),
        ])),
        ("a", symlink("b/c")),
        (b"a/../payload.txt", regular(b"pwned\n")),
    ])),
    meta={
        "vulnerable_when": [
            {"member": "payload.txt"},
            {"member": "b/payload.txt"},
        ],
    },
)

# ── malicious: filesystem-level name collisions ───────────────────────────────

# malicious/case_collision.nar: two entries whose names differ only in ASCII
# case ("FOO" and "foo").  Both are byte-distinct and in valid NAR order
# (uppercase letters sort before lowercase in ASCII).  On case-insensitive
# filesystems (HFS+/APFS default, NTFS on Windows, FAT32) they map to the
# same inode: one silently overwrites the other at extraction time.
gen(
    "malicious/case_collision.nar",
    nar(directory_raw([
        ("FOO", regular(b"uppercase content\n")),
        ("foo", regular(b"lowercase content\n")),
    ])),
)

# malicious/nfkd_collision.nar: "1.txt" (ASCII digit) and "①.txt"
# (U+2460 CIRCLED DIGIT ONE, UTF-8 E2 91 A0).  NFKD normalization decomposes
# ① → 1, so these collide on ext4 casefold (Linux 5.2+), ZFS with NFKD mode,
# and any filesystem that applies compatibility decomposition before comparing.
# Valid NAR order: 0x31 ("1") < 0xE2 ("①").
gen(
    "malicious/nfkd_collision.nar",
    nar(directory_raw([
        ("1.txt", regular(b"ascii content\n")),
        ("①.txt", regular(b"circled content\n")),
    ])),
)

# malicious/fullwidth_collision.nar: "A.txt" (U+0041) and "Ａ.txt"
# (U+FF21 FULLWIDTH LATIN CAPITAL LETTER A, UTF-8 EF BC A1).  NFKD maps
# U+FF21 → U+0041, so these collide on NFKD-normalising filesystems.
# With case folding they additionally collide with "a.txt".
# Valid NAR order: 0x41 < 0xEF.
gen(
    "malicious/fullwidth_collision.nar",
    nar(directory_raw([
        ("A.txt", regular(b"ascii A\n")),
        ("Ａ.txt", regular(b"fullwidth A\n")),
    ])),
)

# malicious/trailing_dot_collision.nar: "foo" and "foo." are byte-distinct
# and in valid NAR order ("foo" is a strict prefix of "foo.").  Win32
# CreateFile silently strips trailing dots, so both names resolve to the
# same file on NTFS/Windows.  The lower-level NtCreateFile does NOT strip,
# so a native extractor can create "foo." — after which normal Win32 access
# to "foo" silently reaches it.
gen(
    "malicious/trailing_dot_collision.nar",
    nar(directory_raw([
        ("foo", regular(b"no dot\n")),
        ("foo.", regular(b"trailing dot\n")),
    ])),
)

# malicious/windows_device_name.nar: entry named "NUL" — a perfectly valid
# POSIX filename, but on Windows "NUL" (case-insensitive) is a reserved device
# name; an extractor writing to it silently discards data.  Windows ignores the
# extension and strips trailing spaces from the base, so "NUL", "NUL.", "NUL.x",
# "NUL.txt", and "NUL .txt" all refer to the null device (empirically tested for
# CON; assumed equivalent for NUL).
# Also covers: CON, PRN, AUX, COM0–COM9, LPT0–LPT9.
gen(
    "malicious/windows_device_name.nar",
    nar(directory([
        ("NUL", regular(b"this data disappears on Windows\n")),
    ])),
)

# malicious/ads_colon.nar: entry named "file.txt:Zone.Identifier".  On NTFS
# a colon creates an Alternate Data Stream on the base file; the stream name
# "Zone.Identifier" is the one Windows uses to mark downloaded content as
# untrusted (Mark-of-the-Web).  An attacker controlling this stream can forge
# or clear the ZoneId, bypassing SmartScreen and open-file warnings.
gen(
    "malicious/ads_colon.nar",
    nar(directory([
        ("file.txt:Zone.Identifier", regular(b"[ZoneTransfer]\nZoneId=0\n")),
    ])),
)

# ── malicious: symlink loop and deep / traversal paths ────────────────────────

# malicious/symlink_loop.nar: "a" → "b" and "b" → "a".  The archive is
# syntactically valid NAR; both entries are well-formed symlinks in correct
# lexicographic order.  A correct extractor creates both symlinks without
# following them.  Any code that follows or verifies symlinks during or after
# extraction (permission propagation, integrity checking, recursive chmod)
# will recurse infinitely or hit the OS ELOOP limit.
gen(
    "malicious/symlink_loop.nar",
    nar(directory([
        ("a", symlink("b")),
        ("b", symlink("a")),
    ])),
)

# malicious/deep_path.nar: a single entry name "a/a/a/a/a/a/a/a/foo.txt" —
# a slash-separated path 8 levels deep encoded as one NAR name token.  A
# correct parser rejects it (slash in name).  A naive extractor that splits
# on "/" creates 8 nested "a" directories and places foo.txt inside; this
# can exhaust PATH_MAX (4096 bytes) or NAME_MAX (255 bytes) buffers, trigger
# stack overflows in recursive descent, or simply escape the declared
# directory structure.
# vulnerable_when: the nested path appears in the walker's output, confirming
# the extractor resolved the slash-separated name into a real directory tree.
gen(
    "malicious/deep_path.nar",
    nar(directory_raw([
        (b"a/a/a/a/a/a/a/a/foo.txt", regular(b"deep\n")),
    ])),
    meta={
        "vulnerable_when": [{"member": "a/a/a/a/a/a/a/a/foo.txt"}],
    },
)

# malicious/dotdot_deep_path.nar: entry name "../../../../../../../foo.txt" —
# 7 consecutive dotdot components followed by "foo.txt", all packed into a
# single NAR name token that contains slashes.  A correct parser rejects
# this (slash in name).  A naive extractor that splits on "/" and resolves
# ".." will traverse 7 levels above the extraction root; on a typical Linux
# tmpdir (depth 2–3 from /) this escapes to / itself.
# vulnerable_when: member "foo.txt" — fires if the extractor resolved the
# traversal and the file landed back at the walker's root (e.g. the tmpdir
# base, one level above the "extracted" subdirectory).
gen(
    "malicious/dotdot_deep_path.nar",
    nar(directory_raw([
        (b"../../../../../../../foo.txt", regular(b"escaped\n")),
    ])),
    meta={
        "vulnerable_when": [{"member": "foo.txt"}],
    },
)

# ── reject: wire-format / type-system violations ──────────────────────────────

# reject/giant_size.nar: the contents length field claims 2^63 bytes.  A
# correct parser must detect that the claimed length is impossible to satisfy
# and reject without allocating or reading 2^63 bytes (OOM / integer overflow).
_GIANT = 1 << 63
gen(
    "reject/giant_size.nar",
    (
        s("nix-archive-1")
        + s("(") + s("type") + s("regular")
        + s("contents")
        + struct.pack("<Q", _GIANT)   # claims 2^63 bytes; nothing follows
    ),
)

# reject/type_twice.nar: the "type" token appears twice inside one node.
# A strict parser expects exactly one "type" field; seeing it again after
# "regular" is already set means an unexpected token at that position.
# A naive parser that loops over fields and last-write-wins would silently
# change the node type from "regular" to "symlink", misinterpreting the entry.
gen(
    "reject/type_twice.nar",
    nar(
        s("(")
        + s("type") + s("regular")    # first: regular
        + s("type") + s("symlink")    # second: invalid; naive parser becomes symlink
        + s("target") + s("/tmp")
        + s(")")
    ),
)

# reject/unknown_type.nar: the "type" field contains an unrecognised value
# ("socket").  NAR defines exactly three types: regular, directory, symlink.
# A correct parser must reject any other value rather than silently skipping
# or inventing behaviour.
gen(
    "reject/unknown_type.nar",
    nar(
        s("(")
        + s("type") + s("socket")
        + s(")")
    ),
)

# reject/executable_symlink.nar: the "executable" marker appears inside a
# symlink node.  The NAR spec restricts "executable" to regular file nodes;
# it has no meaning for symlinks and must be rejected.
gen(
    "reject/executable_symlink.nar",
    nar(
        s("(")
        + s("type") + s("symlink")
        + s("executable") + s("")   # invalid in symlink context
        + s("target") + s("/tmp")
        + s(")")
    ),
)

# reject/null_in_symlink_target.nar: the symlink target contains a null byte.
# C-string symlink(2) callers truncate at the null, resolving to a different
# target ("/etc/passwd") than the encoded string ("/etc/passwd\x00.harmless").
# Mirrors the null_in_name treatment: null bytes in any path-like value must
# be rejected.
gen(
    "reject/null_in_symlink_target.nar",
    (
        s("nix-archive-1")
        + s("(") + s("type") + s("symlink")
        + s("target") + s(b"/etc/passwd\x00.harmless")
        + s(")")
    ),
    meta={
        "vulnerable_when_not": [{"member": "."}],
    },
)

# ── iffy: unusual but syntactically tolerable symlink targets ─────────────────

# iffy/symlink_empty_target.nar: symlink target is an empty string "".
# POSIX allows symlink("", path) to create a dangling symlink to ""; some
# parsers may reject an empty target as meaningless.
gen(
    "iffy/symlink_empty_target.nar",
    nar(symlink("")),
)

# iffy/symlink_long_target.nar: symlink target is 4096 bytes (all 'a').
# zombiezen caps symlinkTargetMaxLen at 4095; this probes that boundary and
# any other static PATH_MAX-sized buffers used to store symlink targets.
gen(
    "iffy/symlink_long_target.nar",
    nar(symlink("a" * 4096)),
)

# iffy/name_noncharacter.nar: entry name contains U+FFFF (\xef\xbf\xbf), a
# Unicode non-character.  Valid UTF-8 encoding; some parsers or tools reject
# non-characters as "not permitted in interchange", others pass them through.
gen(
    "iffy/name_noncharacter.nar",
    nar(directory([
        (b"foo\xef\xbf\xbfbar", regular(b"content\n")),
    ])),
)

# ── malicious: symlink-target attacks ────────────────────────────────────────

# malicious/symlink_dotdot_target.nar: a symlink whose target uses ".." to
# escape the extraction root via a relative path.  Unlike symlink_then_file
# (which relies on a duplicate name to overwrite through the link), this
# archive is structurally valid NAR: one symlink at the root.  The danger
# arises when an extractor follows symlinks during a post-extraction pass
# (recursive chmod, integrity verification, path canonicalisation).
gen(
    "malicious/symlink_dotdot_target.nar",
    nar(symlink("../../etc/passwd")),
)

# ── malicious: resource-fork companion (macOS HFS+/APFS) ─────────────────────

# malicious/resource_fork_companion.nar: a directory containing both "foo"
# (a regular file) and "._foo" (its AppleDouble resource-fork companion).
# On macOS HFS+/APFS, the Finder and many tools treat "._" files as metadata
# for their companion; controlling "._foo" lets an attacker set extended
# attributes, quarantine flags, or code-signing metadata on "foo".
# The entries are in correct NAR order: "._foo" (0x2E) < "foo" (0x66).
gen(
    "malicious/resource_fork_companion.nar",
    nar(directory([
        ("._foo", regular(b"AppleDouble resource fork payload\n")),
        ("foo", regular(b"actual content\n")),
    ])),
)

# malicious/rtl_override_name.nar: entry name contains U+202E RIGHT-TO-LEFT
# OVERRIDE (\xe2\x80\xae).  This causes graphical UIs, terminal emulators and
# web browsers to render the filename in reverse visual order — a file whose
# bytes are "report\xe2\x80\xaegnp.exe" may display as "report‮gnp.exe" and
# look like "exe.pngropert" in an RTL context, disguising an executable as a
# media file.  The name is valid UTF-8 and legal on POSIX.
gen(
    "malicious/rtl_override_name.nar",
    nar(directory([
        ("report\xe2\x80\xaegnp.exe", regular(b"payload\n")),
    ])),
)

# ── malicious: depth / resource-exhaustion attacks ────────────────────────────

# malicious/deep_dirs.nar: 200 levels of legitimate nested directories, each
# named "a", with a regular file at the bottom.  Recursive-descent parsers
# allocate one stack frame (or equivalent) per level; at 200 levels this may
# trigger a stack overflow.  Unlike deep_path.nar (one slash-containing name),
# this uses only well-formed NAR structure and must be accepted by a correct
# parser — the danger is in the extractor or post-processor.


def _nested_dirs(depth: int, leaf: bytes) -> bytes:
    if depth == 0:
        return leaf
    return directory([("a", _nested_dirs(depth - 1, leaf))])


gen(
    "malicious/deep_dirs.nar",
    nar(_nested_dirs(200, regular(b"deep\n"))),
)

# malicious/symlink_loop_subdir.nar: a real subdirectory "a" contains a
# symlink "b" whose target is "../a" — pointing back to the directory
# itself.  Following a/b resolves to a, so a/b/b/b/... is an infinite loop.
# Unlike symlink_loop.nar (two top-level symlinks), this involves a real
# directory one level up, which is harder for a simple "detect symlink→symlink"
# check to catch at parse time.  A correct extractor creates the symlink
# without following it; any tool that recursively traverses the extracted
# tree (chmod, find, rsync) will hit ELOOP or loop forever.
gen(
    "malicious/symlink_loop_subdir.nar",
    nar(directory([
        ("a", directory([
            ("b", symlink("../a")),
        ])),
    ])),
)
