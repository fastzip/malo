import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_src"))

from malo.tar.construct import TarHeader, end_of_archive, gnu_longname, gnu_longlink, pad_data


def gen(filename: str, data: bytes, meta: dict | None = None) -> None:
    Path(filename).write_bytes(data)
    meta_path = Path(filename).with_suffix(".json")
    if meta is not None:
        meta_path.write_text(json.dumps(meta, separators=(", ", ": ")) + "\n")
    elif meta_path.exists():
        meta_path.unlink()


def entry(header: TarHeader, content: bytes = b"") -> bytes:
    return header.pack() + pad_data(content)


def pax_record(key: bytes, value: bytes) -> bytes:
    body = key + b"=" + value + b"\n"
    length = len(body) + 2
    while True:
        digits = str(length).encode()
        new_length = len(digits) + 1 + len(body)
        if new_length == length:
            return digits + b" " + body
        length = new_length


def pax_record_exact(key: bytes, total_len: int) -> bytes:
    for n in range(0, 4096):
        record = pax_record(key, b"a" * n)
        if len(record) == total_len:
            return record
    raise ValueError(f"cannot build {total_len}-byte PAX record for {key!r}")


def pax_header(records: list[tuple[bytes, bytes]], typeflag: bytes = b"x") -> bytes:
    data = b"".join(pax_record(k, v) for k, v in records)
    return entry(TarHeader(name=b"PaxHeader", typeflag=typeflag, size=len(data)), data)


def raw_pax_header(data: bytes) -> bytes:
    return entry(TarHeader(name=b"PaxHeader", typeflag=b"x", size=len(data)), data)


def pax_header_two_block_path(path: bytes, prefix_len: int) -> bytes:
    path_record = pax_record(b"path", path)
    suffix_len = 1024 - prefix_len - len(path_record)
    if suffix_len < 0:
        raise ValueError(f"path record too large for {path!r}")
    data = (
        pax_record_exact(b"comment", prefix_len)
        + path_record
        + pax_record_exact(b"comment", suffix_len)
    )
    return entry(TarHeader(name=b"PaxHeader", typeflag=b"x", size=len(data)), data)


def oldgnu_sparse(name: bytes, sparse: list[tuple[int, int]], realsize: int, data: bytes) -> bytes:
    """Build an old-GNU sparse member with an explicit chunk map."""
    block = bytearray(512)

    def put(off: int, size: int, value: bytes) -> None:
        block[off : off + size] = value[:size].ljust(size, b"\0")

    put(0, 100, name)
    put(100, 8, b"0000644\0")
    put(108, 8, b"0000000\0")
    put(116, 8, b"0000000\0")
    put(124, 12, b"00000000001\0")
    put(136, 12, b"00000000000\0")
    put(148, 8, b"        ")
    put(156, 1, b"S")
    put(157, 100, b"")
    put(257, 6, b"ustar " )
    put(263, 2, b" \x00")
    put(265, 32, b"")
    put(297, 32, b"")
    put(329, 8, b"0000000\0")
    put(337, 8, b"0000000\0")
    put(345, 12, b"00000000000\0")
    put(357, 12, b"00000000000\0")
    put(369, 12, b"00000000000\0")
    put(381, 4, b"")
    block[385] = 0

    for i, (offset, length) in enumerate(sparse[:4]):
        base = 386 + i * 24
        put(base, 12, f"{offset:011o}\0".encode())
        put(base + 12, 12, f"{length:011o}\0".encode())

    block[482] = 0
    put(483, 12, f"{realsize:011o}\0".encode())

    checksum = sum(block)
    block[148:156] = f"{checksum:06o}\0 ".encode()
    return bytes(block) + pad_data(data)


# accept/simple.tar
gen(
    "accept/simple.tar",
    entry(TarHeader(name=b"hello.txt", size=5, mtime=0), b"hello")
    + end_of_archive(),
    {
        "expected": [
            {
                "member": "hello.txt",
                "type": "file",
                "size": 5,
                "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            }
        ]
    },
)

# accept/empty_file.tar
gen(
    "accept/empty_file.tar",
    entry(TarHeader(name=b"empty.txt", size=0))
    + end_of_archive(),
    {
        "expected": [
            {
                "member": "empty.txt",
                "type": "file",
                "size": 0,
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            }
        ]
    },
)

# accept/directory.tar
gen(
    "accept/directory.tar",
    entry(TarHeader(name=b"dir/", mode=0o755, typeflag=b"5"))
    + entry(TarHeader(name=b"dir/file.txt", size=5), b"hello")
    + end_of_archive(),
    {
        "expected": [
            {"member": "dir/", "type": "directory"},
            {
                "member": "dir/file.txt",
                "type": "file",
                "size": 5,
                "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            },
        ]
    },
)

# malicious/dir_with_data.tar: a directory entry that incorrectly carries payload bytes
gen(
    "malicious/dir_with_data.tar",
    entry(TarHeader(name=b"dir/", mode=0o755, typeflag=b"5", size=5), b"hello")
    + end_of_archive(),
    {"vulnerable_when": [{"member": "embedded.txt"}]},
)

# malicious/dir_with_embedded_header.tar: a directory entry whose payload is another tar header
gen(
    "malicious/dir_with_embedded_header.tar",
    entry(
        TarHeader(name=b"dir/", mode=0o755, typeflag=b"5", size=512),
        TarHeader(name=b"embedded.txt", size=5).pack(),
    )
    + end_of_archive(),
    {"vulnerable_when": [{"member": "embedded.txt"}]},
)

# malicious/dir_with_embedded_header_and_pax.tar: a directory payload header says malicious.txt,
# while the later PAX-resolved member should resolve to benign.txt.
gen(
    "malicious/dir_with_embedded_header_and_pax.tar",
    entry(
        TarHeader(name=b"dir/", mode=0o755, typeflag=b"5", size=1024),
        pax_header([(b"path", b"malicious.txt")]),
    )
    + entry(TarHeader(name=b"foo", size=5), b"hello")
    + entry(TarHeader(name=b"bar", size=5), b"hello")
    + end_of_archive(),
    {
        "expected": [
            {
                "member": "benign.txt",
                "type": "file",
                "size": 5,
                "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            }
        ],
        "vulnerable_when": [{"member": "malicious.txt"}],
    },
)

# accept/symlink.tar
gen(
    "accept/symlink.tar",
    entry(TarHeader(name=b"link", typeflag=b"2", linkname=b"target"))
    + end_of_archive(),
    {
        "expected": [{"member": "link", "type": "symlink", "linkname": "target"}]
    },
)

# malicious/symlink_with_data.tar: a symlink entry that incorrectly carries payload bytes
gen(
    "malicious/symlink_with_data.tar",
    entry(TarHeader(name=b"link", typeflag=b"2", linkname=b"target", size=5), b"hello")
    + end_of_archive(),
    {"vulnerable_when": [{"member": "embedded.txt"}]},
)

# malicious/symlink_with_embedded_header.tar: a symlink entry whose payload is another tar header
gen(
    "malicious/symlink_with_embedded_header.tar",
    entry(
        TarHeader(name=b"link", typeflag=b"2", linkname=b"target", size=512),
        TarHeader(name=b"embedded.txt", size=5).pack(),
    )
    + end_of_archive(),
    {"vulnerable_when": [{"member": "embedded.txt"}]},
)

# malicious/hardlink_with_data.tar: a hardlink entry that incorrectly carries payload bytes
gen(
    "malicious/hardlink_with_data.tar",
    entry(TarHeader(name=b"hard.txt", typeflag=b"1", linkname=b"target.txt", size=5), b"hello")
    + end_of_archive(),
    {"vulnerable_when": [{"member": "embedded.txt"}]},
)

# malicious/hardlink_with_embedded_header.tar: a hardlink entry whose payload is another tar header
gen(
    "malicious/hardlink_with_embedded_header.tar",
    entry(
        TarHeader(name=b"hard.txt", typeflag=b"1", linkname=b"target.txt", size=512),
        TarHeader(name=b"embedded.txt", size=5).pack(),
    )
    + end_of_archive(),
    {"vulnerable_when": [{"member": "embedded.txt"}]},
)

# malicious/fifo_with_data.tar: a FIFO entry whose payload is another tar header
gen(
    "malicious/fifo_with_data.tar",
    entry(TarHeader(name=b"fifo0", typeflag=b"6", size=512), TarHeader(name=b"embedded.txt", size=5).pack())
    + end_of_archive(),
    {"vulnerable_when": [{"member": "embedded.txt"}]},
)

# malicious/fifo_with_embedded_header.tar: a FIFO entry whose payload is another tar header
gen(
    "malicious/fifo_with_embedded_header.tar",
    entry(TarHeader(name=b"fifo0", typeflag=b"6", size=512), TarHeader(name=b"embedded.txt", size=5).pack())
    + end_of_archive(),
    {"vulnerable_when": [{"member": "embedded.txt"}]},
)

# malicious/chardev_with_data.tar: a character device entry whose payload is another tar header
gen(
    "malicious/chardev_with_data.tar",
    entry(
        TarHeader(name=b"char0", typeflag=b"3", devmajor=1, devminor=7, size=512),
        TarHeader(name=b"embedded.txt", size=5).pack(),
    )
    + end_of_archive(),
    {"vulnerable_when": [{"member": "embedded.txt"}]},
)

# malicious/chardev_with_embedded_header.tar: a character device entry whose payload is another tar header
gen(
    "malicious/chardev_with_embedded_header.tar",
    entry(
        TarHeader(name=b"char0", typeflag=b"3", devmajor=1, devminor=7, size=512),
        TarHeader(name=b"embedded.txt", size=5).pack(),
    )
    + end_of_archive(),
    {"vulnerable_when": [{"member": "embedded.txt"}]},
)

# malicious/blockdev_with_data.tar: a block device entry whose payload is another tar header
gen(
    "malicious/blockdev_with_data.tar",
    entry(
        TarHeader(name=b"block0", typeflag=b"4", devmajor=8, devminor=0, size=512),
        TarHeader(name=b"embedded.txt", size=5).pack(),
    )
    + end_of_archive(),
    {"vulnerable_when": [{"member": "embedded.txt"}]},
)

# malicious/blockdev_with_embedded_header.tar: a block device entry whose payload is another tar header
gen(
    "malicious/blockdev_with_embedded_header.tar",
    entry(
        TarHeader(name=b"block0", typeflag=b"4", devmajor=8, devminor=0, size=512),
        TarHeader(name=b"embedded.txt", size=5).pack(),
    )
    + end_of_archive(),
    {"vulnerable_when": [{"member": "embedded.txt"}]},
)

# malicious/volume_header_with_data.tar: a volume header entry whose payload is another tar header
gen(
    "malicious/volume_header_with_data.tar",
    entry(
        TarHeader(name=b"volume", typeflag=b"V", size=512),
        TarHeader(name=b"embedded.txt", size=5).pack(),
    )
    + end_of_archive(),
    {"vulnerable_when": [{"member": "embedded.txt"}]},
)

# malicious/volume_header_with_embedded_header.tar: a volume header entry whose payload is another tar header
gen(
    "malicious/volume_header_with_embedded_header.tar",
    entry(
        TarHeader(name=b"volume", typeflag=b"V", size=512),
        TarHeader(name=b"embedded.txt", size=5).pack(),
    )
    + end_of_archive(),
    {"vulnerable_when": [{"member": "embedded.txt"}]},
)

# malicious/dumpdir_with_data.tar: a GNU dumpdir entry whose payload is another tar header
gen(
    "malicious/dumpdir_with_data.tar",
    entry(
        TarHeader(name=b"dumpdir", typeflag=b"D", size=512),
        TarHeader(name=b"embedded.txt", size=5).pack(),
    )
    + end_of_archive(),
    {"vulnerable_when": [{"member": "embedded.txt"}]},
)

# malicious/dumpdir_with_embedded_header.tar: a GNU dumpdir entry whose payload is another tar header
gen(
    "malicious/dumpdir_with_embedded_header.tar",
    entry(
        TarHeader(name=b"dumpdir", typeflag=b"D", size=512),
        TarHeader(name=b"embedded.txt", size=5).pack(),
    )
    + end_of_archive(),
    {"vulnerable_when": [{"member": "embedded.txt"}]},
)

# malicious/contiguous_with_data.tar: a contiguous file entry whose payload is another tar header
gen(
    "malicious/contiguous_with_data.tar",
    entry(
        TarHeader(name=b"contig.txt", typeflag=b"7", size=512),
        TarHeader(name=b"embedded.txt", size=5).pack(),
    )
    + end_of_archive(),
    {"vulnerable_when": [{"member": "embedded.txt"}]},
)

# malicious/contiguous_with_embedded_header.tar: a contiguous file entry whose payload is another tar header
gen(
    "malicious/contiguous_with_embedded_header.tar",
    entry(
        TarHeader(name=b"contig.txt", typeflag=b"7", size=512),
        TarHeader(name=b"embedded.txt", size=5).pack(),
    )
    + end_of_archive(),
    {"vulnerable_when": [{"member": "embedded.txt"}]},
)

# reject/gnu_longname.tar: GNU L extension — corpus only validates PAX
_long = b"a" * 50 + b"/" + b"b" * 80 + b".txt"
gen(
    "reject/gnu_longname.tar",
    gnu_longname(_long)
    + entry(TarHeader(name=_long[:100], size=5), b"hello")
    + end_of_archive(),
)

# iffy/regular_nul.tar: typeflag \0 is pre-POSIX V7; PAX uses '0'
gen(
    "iffy/regular_nul.tar",
    entry(TarHeader(name=b"nul.txt", typeflag=b"\0", size=5), b"hello")
    + end_of_archive(),
)

# GNU tar: "Global extended header"
gen(
    "accept/global_pax.tar",
    pax_header([(b"mtime", b"0")], typeflag=b"g")
    + entry(TarHeader(name=b"global.txt", size=5), b"hello")
    + end_of_archive(),
)

# GNU tar: "Extended header referring to the next file in the archive"
gen(
    "accept/pax_extended_header.tar",
    pax_header([(b"path", b"from-x.txt")], typeflag=b"x")
    + entry(TarHeader(name=b"ignored", size=5), b"hello")
    + end_of_archive(),
)

# reject/gnu_longlink.tar: GNU K extension — corpus only validates PAX
gen(
    "reject/gnu_longlink.tar",
    gnu_longlink(b"target")
    + entry(TarHeader(name=b"link", typeflag=b"1", linkname=b"target"))
    + end_of_archive(),
)

# iffy/no_magic.tar: magic field all zeros — pre-POSIX V7 format
gen(
    "iffy/no_magic.tar",
    entry(TarHeader(name=b"file.txt", size=5, magic=b"\x00" * 6, version=b"\x00\x00"), b"hello")
    + end_of_archive(),
)

# iffy/gnu_magic.tar: GNU-style magic ("ustar ") and version (" \x00")
gen(
    "iffy/gnu_magic.tar",
    entry(TarHeader(name=b"file.txt", size=5, magic=b"ustar ", version=b" \x00"), b"hello")
    + end_of_archive(),
)

# iffy/name_no_nul.tar: name field uses all 100 bytes with no NUL terminator
gen(
    "iffy/name_no_nul.tar",
    entry(TarHeader(name=b"x" * 100, size=5), b"hello")
    + end_of_archive(),
)

# iffy/empty_name.tar: zero-length filename string in the tar header
gen(
    "iffy/empty_name.tar",
    entry(TarHeader(name=b"", size=5), b"hello")
    + end_of_archive(),
)

# iffy/backslash_name.tar: backslash is a literal byte in tar names
gen(
    "iffy/backslash_name.tar",
    entry(TarHeader(name=b"dir\\file.txt", size=5), b"hello")
    + end_of_archive(),
)

# iffy/sparse_no_chunks_zero.tar: sparse type without a chunk map and zero logical size
gen(
    "iffy/sparse_no_chunks_zero.tar",
    oldgnu_sparse(
        name=b"sparse_zero",
        sparse=[],
        realsize=0,
        data=b"",
    )
    + end_of_archive(),
)

# iffy/sparse_no_chunks_nonzero.tar: sparse type without a chunk map and nonzero logical size
gen(
    "iffy/sparse_no_chunks_nonzero.tar",
    oldgnu_sparse(
        name=b"sparse_nonzero",
        sparse=[],
        realsize=123,
        data=b"",
    )
    + end_of_archive(),
)

# iffy/sparse_zero_chunk.tar: sparse type with an explicit zero-length chunk
gen(
    "iffy/sparse_zero_chunk.tar",
    oldgnu_sparse(
        name=b"sparse_zero_chunk",
        sparse=[(0, 0)],
        realsize=123,
        data=b"",
    )
    + end_of_archive(),
)

# iffy/unknown_A_zero.tar: unknown typeflag with no payload
gen(
    "iffy/unknown_A_zero.tar",
    entry(TarHeader(name=b"unknown_zero", typeflag=b"A", size=0))
    + end_of_archive(),
)

# iffy/unknown_A_data.tar: unknown typeflag with a data payload
gen(
    "iffy/unknown_A_data.tar",
    entry(TarHeader(name=b"unknown_data", typeflag=b"A", size=5), b"hello")
    + end_of_archive(),
)

# accept/pax_path_empty_fixed.tar: PAX path fills in an empty fixed-header name
gen(
    "accept/pax_path_empty_fixed.tar",
    pax_header([(b"path", b"filled-from-pax.txt")])
    + entry(TarHeader(name=b"", size=5), b"hello")
    + end_of_archive(),
)

# iffy/pax_path_nonzero_fixed.tar: PAX path overrides a non-empty fixed-header name
gen(
    "iffy/pax_path_nonzero_fixed.tar",
    pax_header([(b"path", b"override-from-pax.txt")])
    + entry(TarHeader(name=b"legacy-fixed-name.txt", size=5), b"hello")
    + end_of_archive(),
    {
        "vulnerable_when": [
            {"member": "override-from-pax.txt"},
            {"member": "legacy-fixed-name.txt"},
        ]
    },
)

# iffy/pax_path_second_block.tar: the PAX path first appears in the second 512-byte payload block
gen(
    "iffy/pax_path_second_block.tar",
    pax_header_two_block_path(b"late-in-second-block.txt", 512)
    + entry(TarHeader(name=b"legacy-fixed-name.txt", size=5), b"hello")
    + end_of_archive(),
    {
        "vulnerable_when_not": [
            {"member": "late-in-second-block.txt"},
        ]
    },
)

# malicious/pax_path_key_split.tar: the PAX key name itself crosses the block boundary
gen(
    "malicious/pax_path_key_split.tar",
    pax_header_two_block_path(b"split-key.txt", 510)
    + entry(TarHeader(name=b"legacy-fixed-name.txt", size=5), b"hello")
    + end_of_archive(),
    {
        "vulnerable_when_not": [
            {"member": "split-key.txt"},
        ]
    },
)

# malicious/pax_path_value_split.tar: the filename value itself crosses the block boundary
gen(
    "malicious/pax_path_value_split.tar",
    pax_header_two_block_path(b"split-name.txt", 500)
    + entry(TarHeader(name=b"legacy-fixed-name.txt", size=5), b"hello")
    + end_of_archive(),
    {
        "vulnerable_when_not": [
            {"member": "split-name.txt"},
        ]
    },
)

# malicious/path_traversal.tar
gen(
    "malicious/path_traversal.tar",
    entry(TarHeader(name=b"../../etc/passwd", size=5), b"hello")
    + end_of_archive(),
)

# malicious/absolute_path.tar
gen(
    "malicious/absolute_path.tar",
    entry(TarHeader(name=b"/etc/passwd", size=5), b"hello")
    + end_of_archive(),
)

# reject/sparse_basic.tar: old-GNU sparse format — corpus only validates PAX
gen(
    "reject/sparse_basic.tar",
    oldgnu_sparse(
        name=b"sparse_basic",
        sparse=[(0, 1)],
        realsize=1 << 20,
        data=b"X",
    )
    + end_of_archive(),
)

# malicious/sparse_huge.tar: old-GNU sparse file with a tiny payload and 1 GiB logical size
gen(
    "malicious/sparse_huge.tar",
    oldgnu_sparse(
        name=b"sparse_huge",
        sparse=[(0, 1)],
        realsize=1 << 30,
        data=b"X",
    )
    + end_of_archive(),
)

# GNU tar: "This is a dir entry that contains the names of files that were in the dir at the time the dump was made."
gen(
    "malicious/dumpdir.tar",
    entry(TarHeader(name=b"dumpdir", typeflag=b"D", size=5), b"Yfoo\0")
    + end_of_archive(),
)

# GNU tar: "This file type is used to mark the volume header"
gen(
    "malicious/volume_header.tar",
    entry(TarHeader(name=b"volume", typeflag=b"V", size=0))
    + end_of_archive(),
)

# GNU tar: "This flag represents a file linked to another file"
gen(
    "malicious/hardlink.tar",
    entry(TarHeader(name=b"target.txt", size=5), b"hello")
    + entry(TarHeader(name=b"hard.txt", typeflag=b"1", linkname=b"target.txt"))
    + end_of_archive(),
)

# GNU tar: "This represents a symbolic link to another file"
gen(
    "malicious/symlink.tar",
    entry(TarHeader(name=b"target.txt", size=5), b"hello")
    + entry(TarHeader(name=b"sym.txt", typeflag=b"2", linkname=b"target.txt"))
    + end_of_archive(),
)

# GNU tar: "character special files and block special files respectively"
gen(
    "malicious/chardev.tar",
    entry(TarHeader(name=b"char0", typeflag=b"3", devmajor=1, devminor=7))
    + end_of_archive(),
)

gen(
    "malicious/blockdev.tar",
    entry(TarHeader(name=b"block0", typeflag=b"4", devmajor=8, devminor=0))
    + end_of_archive(),
)

# GNU tar: "This specifies a FIFO special file."
gen(
    "malicious/fifo.tar",
    entry(TarHeader(name=b"fifo0", typeflag=b"6"))
    + end_of_archive(),
)

# GNU tar: "This specifies a contiguous file"
gen(
    "malicious/contiguous.tar",
    entry(TarHeader(name=b"contig.txt", typeflag=b"7", size=5), b"hello")
    + end_of_archive(),
)

# malicious/prefix_dir_name_empty.tar: prefix without a trailing slash, empty name, directory member
gen(
    "malicious/prefix_dir_name_empty.tar",
    entry(TarHeader(name=b"", prefix=b"dir", typeflag=b"5"))
    + end_of_archive(),
)

# malicious/prefix_empty_name_dot.tar: empty prefix, name is '.', directory member
gen(
    "malicious/prefix_empty_name_dot.tar",
    entry(TarHeader(name=b".", typeflag=b"5"))
    + end_of_archive(),
)

# malicious/prefix_empty_name_empty.tar: empty prefix and empty name, directory member
gen(
    "malicious/prefix_empty_name_empty.tar",
    entry(TarHeader(name=b"", typeflag=b"5"))
    + end_of_archive(),
)

# malicious/prefix_empty_name_slashfoo.tar: empty prefix, name starts with slash
gen(
    "malicious/prefix_empty_name_slashfoo.tar",
    entry(TarHeader(name=b"/foo", typeflag=b"5"))
    + end_of_archive(),
)

# reject/prefix_empty_name_empty_reg.tar: empty prefix and empty name for a regular file
gen(
    "reject/prefix_empty_name_empty_reg.tar",
    entry(TarHeader(name=b"", typeflag=b"0"))
    + end_of_archive(),
)

# malicious/prefix_dot_name_foo.tar: prefix is '.', name is 'foo', directory member
gen(
    "malicious/prefix_dot_name_foo.tar",
    entry(TarHeader(name=b"foo", prefix=b".", typeflag=b"5"))
    + end_of_archive(),
)

# reject/prefix_dot_name_foo_reg.tar: prefix is '.', name is 'foo', regular file
gen(
    "reject/prefix_dot_name_foo_reg.tar",
    entry(TarHeader(name=b"foo", prefix=b".", typeflag=b"0"))
    + end_of_archive(),
)

# malicious/pax_duplicate_name.tar: two names that normalize to the same Unicode string
# NFC: café.txt / NFD: café.txt
gen(
    "malicious/pax_duplicate_name.tar",
    pax_header([(b"path", "café.txt".encode("utf-8"))])
    + entry(TarHeader(name=b"ignored", size=5), b"first")
    + pax_header([(b"path", "café.txt".encode("utf-8"))])
    + entry(TarHeader(name=b"ignored", size=6), b"second")
    + end_of_archive(),
    {
        "expected": [
            {
                "member": "café.txt",
                "type": "file",
                "size": 5,
                "sha256": "a7937b64b8caa58f03721bb6bacf5aa43df4a9e50bd3cfe03134564e1f9a1a15",
            },
            {
                "member": "café.txt",
                "type": "file",
                "size": 6,
                "sha256": "16367aacb67a4a017c8da8ab95681c2e7e4bae6f3c9d2a0e4a3b7d8a7bff3bfb",
            },
        ]
    },
)

# malicious/pax_duplicate_exact.tar: two PAX entries with the same final pathname
gen(
    "malicious/pax_duplicate_exact.tar",
    pax_header([(b"path", b"same.txt")])
    + entry(TarHeader(name=b"ignored", size=5), b"first")
    + pax_header([(b"path", b"same.txt")])
    + entry(TarHeader(name=b"ignored", size=6), b"second")
    + end_of_archive(),
    {
        "expected": [
            {
                "member": "same.txt",
                "type": "file",
                "size": 5,
                "sha256": "a7937b64b8caa58f03721bb6bacf5aa43df4a9e50bd3cfe03134564e1f9a1a15",
            },
            {
                "member": "same.txt",
                "type": "file",
                "size": 6,
                "sha256": "16367aacb67a4a017c8da8ab95681c2e7e4bae6f3c9d2a0e4a3b7d8a7bff3bfb",
            },
        ]
    },
)

# malicious/nonpax_duplicate_name.tar: two plain tar members with the same pathname
gen(
    "malicious/nonpax_duplicate_name.tar",
    entry(TarHeader(name=b"same.txt", size=5), b"first")
    + entry(TarHeader(name=b"same.txt", size=6), b"second")
    + end_of_archive(),
    {
        "expected": [
            {
                "member": "same.txt",
                "type": "file",
                "size": 5,
                "sha256": "a7937b64b8caa58f03721bb6bacf5aa43df4a9e50bd3cfe03134564e1f9a1a15",
            },
            {
                "member": "same.txt",
                "type": "file",
                "size": 6,
                "sha256": "16367aacb67a4a017c8da8ab95681c2e7e4bae6f3c9d2a0e4a3b7d8a7bff3bfb",
            },
        ]
    },
)

# malicious/pax_multiple_headers.tar: more than one extended PAX header before a file
gen(
    "malicious/pax_multiple_headers.tar",
    pax_header([(b"path", b"first.txt")])
    + pax_header([(b"mtime", b"0")])
    + entry(TarHeader(name=b"ignored", size=5), b"hello")
    + end_of_archive(),
    {
        "expected": [
            {
                "member": "first.txt",
                "type": "file",
                "size": 5,
                "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            }
        ]
    },
)

# malicious/pax_binary_mode_names.tar: PAX hdrcharset=BINARY plus a Latin-1 path
gen(
    "malicious/pax_binary_mode_names.tar",
    pax_header([(b"hdrcharset", b"BINARY"), (b"path", b"caf\xe9.txt")])
    + entry(TarHeader(name=b"ignored", size=5), b"hello")
    + end_of_archive(),
    {
        "vulnerable_when": [{"member": "café.txt"}],
        "vulnerable_when_not": [{"member": "caf\udce9.txt"}],
    },
)

# malicious/pax_iso88591_hdrcharset.tar: hdrcharset=ISO-8859-1 with a Latin-1 path byte.
# POSIX allows extra charsets "agreed between originator and recipient", so ISO-8859-1 is legal.
# No oracle decodes \xe9 as ISO-8859-1; each mangles it differently:
#   bsdtar/c/zig: reject. gnutar/python: surrogate-escape (caf\udce9.txt).
#   go: JSON-escapes U+FFFD (caf�.txt). rust/java/dotnet: literal U+FFFD.
#   nodejs: ignores the PAX header entirely, falls back to fixed-header name "ignored".
gen(
    "malicious/pax_iso88591_hdrcharset.tar",
    pax_header([(b"hdrcharset", b"ISO-8859-1"), (b"path", b"caf\xe9.txt")])
    + entry(TarHeader(name=b"ignored", size=5), b"hello")
    + end_of_archive(),
    {"vulnerable_when": [{"member": "café.txt"}]},
)

# malicious/pax_bad_hdrcharset_ascii.tar: bogus hdrcharset with an otherwise normal ASCII path
gen(
    "malicious/pax_bad_hdrcharset_ascii.tar",
    pax_header([(b"hdrcharset", b"xxx"), (b"path", b"normal.txt")])
    + entry(TarHeader(name=b"ignored", size=5), b"hello")
    + end_of_archive(),
    {
        "expected": [
            {
                "member": "normal.txt",
                "type": "file",
                "size": 5,
                "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            }
        ]
    },
)

# malicious/zero_blocks_middle.tar: two EOF blocks in the middle, then another valid member
gen(
    "malicious/zero_blocks_middle.tar",
    entry(TarHeader(name=b"first.txt", size=5), b"hello")
    + end_of_archive()
    + entry(TarHeader(name=b"second.txt", size=5), b"world")
    + end_of_archive(),
    {
        "vulnerable_when": [{"member": "second.txt"}],
    },
)

# malicious/pax_utf16_hdrcharset.tar: hdrcharset=BINARY plus a UTF-16LE path payload
gen(
    "malicious/pax_utf16_hdrcharset.tar",
    pax_header([(b"hdrcharset", b"BINARY"), (b"path", "utf16-name.txt".encode("utf-16le"))])
    + entry(TarHeader(name=b"ignored", size=5), b"hello")
    + end_of_archive(),
    {"vulnerable_when": [{"member": "utf16-name.txt"}]},
)

# iffy/pax_utf16_hdrcharset_utf16.tar: hdrcharset=utf-16 plus a UTF-16LE path payload
gen(
    "iffy/pax_utf16_hdrcharset_utf16.tar",
    pax_header([(b"hdrcharset", b"utf-16"), (b"path", "utf16-name.txt".encode("utf-16le"))])
    + entry(TarHeader(name=b"ignored", size=5), b"hello")
    + end_of_archive(),
)

# iffy/pax_utf16_hdrcharset_UTF16.tar: hdrcharset=UTF16 plus a UTF-16LE path payload
gen(
    "iffy/pax_utf16_hdrcharset_UTF16.tar",
    pax_header([(b"hdrcharset", b"UTF16"), (b"path", "utf16-name.txt".encode("utf-16le"))])
    + entry(TarHeader(name=b"ignored", size=5), b"hello")
    + end_of_archive(),
)

# malicious/pax_null_in_string.tar: PAX path contains an embedded NUL byte
gen(
    "malicious/pax_null_in_string.tar",
    pax_header([(b"path", b"null\x00byte.txt")])
    + entry(TarHeader(name=b"ignored", size=5), b"hello")
    + end_of_archive(),
    {"vulnerable_when": [{"member": "null"}]},
)

# malicious/pax_null_at_end_of_key.tar: NUL byte at the end of the key, just before '='.
# Record bytes: "17 path\x00=evil.txt\n". bsdtar C-string-truncates the key to "path" and
# extracts evil.txt — a path injection invisible to every other parser, which all ignore
# the record (unrecognised key) and fall back to the fixed-header name.
gen(
    "malicious/pax_null_at_end_of_key.tar",
    raw_pax_header(pax_record(b"path\x00", b"evil.txt"))
    + entry(TarHeader(name=b"fallback.txt", size=5), b"hello")
    + end_of_archive(),
    {"vulnerable_when": [{"member": "evil.txt"}]},
)

# reject/pax_null_in_key.tar: NUL byte in the middle of the key ("pa\x00th=evil.txt").
# gnutar and go reject; bsdtar and most others silently ignore the record (unrecognised key)
# and fall back to the fixed-header name. No parser extracts evil.txt.
gen(
    "reject/pax_null_in_key.tar",
    raw_pax_header(pax_record(b"pa\x00th", b"evil.txt"))
    + entry(TarHeader(name=b"fallback.txt", size=5), b"hello")
    + end_of_archive(),
)

# reject/pax_no_equals.tar: PAX record with no '=' separator ("7 path\n").
# bsdtar/gnutar/go/dotnet reject. python raises InvalidHeaderError and tarfile.open()
# exhausts all format probes (gz/bz2/xz/tar), producing a confusing multi-format error.
# rust/nodejs/java silently skip the record and use the fixed-header name.
_no_eq = b"7 path\n"  # length=7, body has no '='
gen(
    "reject/pax_no_equals.tar",
    raw_pax_header(_no_eq)
    + entry(TarHeader(name=b"fallback.txt", size=5), b"hello")
    + end_of_archive(),
)

# reject/pax_missing_newline.tar: PAX record with the trailing '\n' stripped.
# bsdtar/gnutar/python/go/dotnet/java reject. rust and nodejs silently accept.
_good = pax_record(b"path", b"nonewline.txt")
gen(
    "reject/pax_missing_newline.tar",
    raw_pax_header(_good[:-1])  # strip the final \n
    + entry(TarHeader(name=b"fallback.txt", size=5), b"hello")
    + end_of_archive(),
)

# malicious/pax_overlong_utf8.tar: PAX path uses an overlong UTF-8 encoding
# Here the slash in "dir/name.txt" is encoded as the invalid overlong sequence C0 AF.
gen(
    "malicious/pax_overlong_utf8.tar",
    pax_header([(b"path", b"dir\xc0\xafname.txt")])
    + entry(TarHeader(name=b"ignored", size=5), b"hello")
    + end_of_archive(),
)

# iffy/pax_utf16_name.tar: a path encoded as UTF-16LE inside a PAX header
# This is non-standard but still structurally readable.
gen(
    "iffy/pax_utf16_name.tar",
    pax_header([(b"path", "utf16-name.txt".encode("utf-16le"))])
    + entry(TarHeader(name=b"ignored", size=5), b"hello")
    + end_of_archive(),
)

# malicious/pax_global_size.tar: a global PAX header that tries to set a file-specific size
gen(
    "malicious/pax_global_size.tar",
    pax_header([(b"size", b"0")], typeflag=b"g")
    + entry(TarHeader(name=b"global-size.txt", size=5), b"hello")
    + end_of_archive(),
    {
        "expected": [
            {
                "member": "global-size.txt",
                "type": "file",
                "size": 5,
                "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            }
        ]
    },
)

# reject/bad_checksum.tar: explicitly wrong checksum
gen(
    "reject/bad_checksum.tar",
    entry(TarHeader(name=b"file.txt", size=5, checksum=0), b"hello")
    + end_of_archive(),
)

# reject/truncated.tar: header declares size=100, but stream ends after 5 bytes
gen(
    "reject/truncated.tar",
    TarHeader(name=b"file.txt", size=100).pack() + b"short",
)

# reject/nonoctal_size.tar: size field contains non-octal characters
_header = TarHeader(name=b"file.txt", size=5).pack()
_bad = bytearray(_header)
_bad[124:130] = b"fghijk"    # overwrite size field with non-octal bytes
gen(
    "reject/nonoctal_size.tar",
    bytes(_bad) + pad_data(b"hello") + end_of_archive(),
)


def pax_sparse_01(
    name: bytes,
    realsize: int,
    chunks: list[tuple[int, int]],
    data: bytes,
) -> bytes:
    """PAX sparse format 0.1: GNU.sparse.* attributes in extended header."""
    map_val = b",".join(
        f"{off},{sz}".encode() for off, sz in chunks
    )
    records = [
        (b"GNU.sparse.major", b"0"),
        (b"GNU.sparse.minor", b"1"),
        (b"GNU.sparse.name", name),
        (b"GNU.sparse.realsize", str(realsize).encode()),
        (b"GNU.sparse.numblocks", str(len(chunks)).encode()),
        (b"GNU.sparse.map", map_val),
    ]
    return (
        pax_header(records)
        + entry(TarHeader(name=name, size=len(data)), data)
    )


# iffy/pax_sparse_basic.tar: well-formed GNU.sparse 0.1; parsers may refuse sparse
gen(
    "iffy/pax_sparse_basic.tar",
    pax_sparse_01(name=b"sparse.txt", realsize=4096, chunks=[(0, 5)], data=b"hello")
    + end_of_archive(),
)

# reject/pax_sparse_map_overflow.tar: chunk extends past realsize
gen(
    "reject/pax_sparse_map_overflow.tar",
    pax_sparse_01(name=b"sparse.txt", realsize=20, chunks=[(100, 50)], data=b"hello" * 10)
    + end_of_archive(),
)

# reject/pax_sparse_numblocks_mismatch.tar: numblocks=3 but map has only 1 entry
gen(
    "reject/pax_sparse_numblocks_mismatch.tar",
    pax_header([
        (b"GNU.sparse.major", b"0"),
        (b"GNU.sparse.minor", b"1"),
        (b"GNU.sparse.name", b"sparse.txt"),
        (b"GNU.sparse.realsize", b"4096"),
        (b"GNU.sparse.numblocks", b"3"),
        (b"GNU.sparse.map", b"0,5"),
    ])
    + entry(TarHeader(name=b"sparse.txt", size=5), b"hello")
    + end_of_archive(),
)

# --- differential research: 10 new cases targeting python vs rust_uv ---

# malicious/pax_local_size_override.tar: PAX size=3 vs fixed header size=5, content=hello
# Python (tarfile) uses PAX size → reads "hel" (sha256=d6a8...).
# rust_uv (tokio-tar) may use fixed size → reads "hello" (sha256=2cf2...).
# Both parsers advance the same 512-byte data block, so both should exit 0.
gen(
    "malicious/pax_local_size_override.tar",
    pax_header([(b"path", b"file.txt"), (b"size", b"3")])
    + entry(TarHeader(name=b"ignored", size=5), b"hello")
    + end_of_archive(),
)

# malicious/pax_two_paths_evil_first.tar: two path= records in one PAX block
# First: ../evil.txt  Second: safe.txt
# POSIX last-wins → safe.txt. A first-wins bug gives ../evil.txt.
# Rust unpack_in rejects ../evil.txt (traversal), so first-wins → Rust exits 1.
gen(
    "malicious/pax_two_paths_evil_first.tar",
    pax_header([(b"path", b"../evil.txt"), (b"path", b"safe.txt")])
    + entry(TarHeader(name=b"ignored", size=5), b"hello")
    + end_of_archive(),
    {"vulnerable_when": [{"member": "../evil.txt"}]},
)

# malicious/pax_two_paths_evil_last.tar: two path= records, last wins per spec
# First: first.txt  Second: last.txt
# If a parser uses first-wins instead of last-wins, it extracts first.txt instead of last.txt.
gen(
    "malicious/pax_two_paths_evil_last.tar",
    pax_header([(b"path", b"first.txt"), (b"path", b"last.txt")])
    + entry(TarHeader(name=b"ignored", size=5), b"hello")
    + end_of_archive(),
    {"vulnerable_when_not": [{"member": "last.txt"}]},
)

# malicious/pax_dotslash_path.tar: PAX path starts with ./
# Python tarfile yields ./hello.txt unchanged; rust_uv Path normalization may strip it.
gen(
    "malicious/pax_dotslash_path.tar",
    pax_header([(b"path", b"./hello.txt")])
    + entry(TarHeader(name=b"ignored", size=5), b"hello")
    + end_of_archive(),
)

# malicious/pax_linkpath_symlink.tar: PAX linkpath= for symlink target
# Fixed linkname=../evil_target; PAX linkpath=safe_target.
# Python tarfile honors linkpath= → reports safe_target.
# rust_uv (tokio-tar) may ignore linkpath= and fall back to ../evil_target.
gen(
    "malicious/pax_linkpath_symlink.tar",
    pax_header([(b"path", b"link.txt"), (b"linkpath", b"safe_target")])
    + entry(TarHeader(name=b"link.txt", typeflag=b"2", linkname=b"../evil_target"))
    + end_of_archive(),
)

# malicious/pax_global_path.tar: global 'g' PAX header sets path=from_global.txt
# No local 'x' header follows; plain entry has fixed name=fixed.txt.
# Python applies global path= to rename the following member → from_global.txt.
# rust_uv yields the 'g' header itself as a PaxHeader entry and keeps fixed name → fixed.txt.
# If an attacker controls the 'g' path=, Python is susceptible to global path injection.
gen(
    "malicious/pax_global_path.tar",
    pax_header([(b"path", b"from_global.txt")], typeflag=b"g")
    + entry(TarHeader(name=b"fixed.txt", size=5), b"hello")
    + end_of_archive(),
    {"vulnerable_when": [{"member": "from_global.txt"}]},
)

# malicious/pax_path_trailing_slash_file.tar: regular file but PAX path ends with /
# Python strips the trailing slash → file.txt.
# rust_uv keeps the trailing slash → file.txt/.
# Retaining a trailing slash on a non-directory entry is ambiguous and may confuse consumers.
gen(
    "malicious/pax_path_trailing_slash_file.tar",
    pax_header([(b"path", b"file.txt/")])
    + entry(TarHeader(name=b"ignored", size=5), b"hello")
    + end_of_archive(),
    {"vulnerable_when": [{"member": "file.txt/"}]},
)

# iffy/pax_empty_path.tar: PAX path= with empty value
# Python tarfile falls back to the fixed name field.
# rust_uv may use an empty string or reject.
gen(
    "iffy/pax_empty_path.tar",
    pax_header([(b"path", b"")])
    + entry(TarHeader(name=b"fixed.txt", size=5), b"hello")
    + end_of_archive(),
)

# malicious/pax_path_cr.tar: PAX path contains a carriage return
# Python includes \r in member name; rust_uv may strip it.
gen(
    "malicious/pax_path_cr.tar",
    pax_header([(b"path", b"evil\r.txt")])
    + entry(TarHeader(name=b"ignored", size=5), b"hello")
    + end_of_archive(),
)

# iffy/pax_record_leading_zero_length.tar: PAX length field has a leading zero
# "011 path=h\n" is 11 bytes; length "011" = 11 in decimal (self-consistent).
# POSIX format says %d (no leading zeros), so strict parsers may reject.
_pax_lz = b"011 path=h\n"  # 11 bytes; length field "011" == 11 decimal
gen(
    "iffy/pax_record_leading_zero_length.tar",
    entry(TarHeader(name=b"PaxHeader", typeflag=b"x", size=len(_pax_lz)), _pax_lz)
    + entry(TarHeader(name=b"h", size=5), b"hello")
    + end_of_archive(),
)

# malicious/pax_path_and_prefix_traversal.tar: PAX path=safe.txt but fixed prefix=../../..
# POSIX: when PAX path= is present, the fixed prefix and name fields must be ignored.
# A buggy parser that uses prefix+name → ../../../evil.txt (path traversal).
gen(
    "malicious/pax_path_and_prefix_traversal.tar",
    pax_header([(b"path", b"safe.txt")])
    + entry(TarHeader(name=b"evil.txt", prefix=b"../../..", size=5), b"hello")
    + end_of_archive(),
    {"vulnerable_when": [{"member": "../../../evil.txt"}]},
)

# malicious/pax_x_then_g_drops_path.tar: local 'x' header sets path=../evil.txt, then a
# global 'g' header (mtime=0) follows before the actual file entry (fixed name=safe.txt).
# Python tarfile: _proc_pax for 'x' calls _fromtarfile which recurses through 'g' transparently
#   and applies 'x' PAX to the final file → ../evil.txt (path traversal).
# astral-tokio-tar: has no 'g' handler; 'g' falls through to the line-476 path which consumes
#   the single PAX slot. Oracle skips the 'g' entry. File gets no PAX → safe.txt.
# An attacker can interpose a 'g' header to suppress path traversal detection in astral
# while still triggering it in Python.
gen(
    "malicious/pax_x_then_g_drops_path.tar",
    pax_header([(b"path", b"../evil.txt")])
    + pax_header([(b"mtime", b"0")], typeflag=b"g")
    + entry(TarHeader(name=b"safe.txt", size=5), b"hello")
    + end_of_archive(),
    {"vulnerable_when": [{"member": "../evil.txt"}]},
)

# malicious/pax_global_size_local_path.tar: global 'g' sets size=3; local 'x' sets path=local.txt;
# actual file has fixed size=5 and content "hello".
# Python: 'g' sets tarfile.pax_headers["size"]="3"; 'x' copies that into its local pax_headers
#   (x has no size= of its own); applies size=3 to the file → reads only "hel" (3 bytes).
# astral-tokio-tar: no global PAX accumulator; 'g' falls through and is skipped by the oracle;
#   'x' attaches path=local.txt to the file; poll_next_raw finds no size= in the PAX → uses
#   the fixed header size=5 → reads "hello" (5 bytes).
# sha256("hel")   = d6a81f224bbf2f7c22baddbd5d40730eb20cfb0b3d74e10cab61788214caceb1
# sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
# (content differential only — same member name; use --hash to see it in the table)
gen(
    "malicious/pax_global_size_local_path.tar",
    pax_header([(b"size", b"3")], typeflag=b"g")
    + pax_header([(b"path", b"local.txt")])
    + entry(TarHeader(name=b"fixed.txt", size=5), b"hello")
    + end_of_archive(),
)
