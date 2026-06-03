import mmap
import struct
import sys
import zipfile
import zlib
from io import BytesIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_src"))

A = b"# benign\n"
B = b"print('malicious')\n# 12323013111123311000\n"


def prefix_copy(dest: str, src: str, prefix: bytes = b"X") -> None:
    Path(dest).write_bytes(prefix + Path(src).read_bytes())


def truncate_cd_size(dest: str, src: str, new_size: int) -> None:
    data = bytearray(Path(src).read_bytes())
    lfh_off = data.find(b"PK\x03\x04")
    assert lfh_off != -1
    fn_len = struct.unpack_from("<H", data, lfh_off + 26)[0]
    extra_len = struct.unpack_from("<H", data, lfh_off + 28)[0]
    payload_off = lfh_off + 30 + fn_len + extra_len
    payload = data[payload_off : payload_off + new_size]
    eocd = data.rfind(b"PK\x05\x06")
    assert eocd != -1
    cd_off = struct.unpack_from("<I", data, eocd + 16)[0]
    assert data[cd_off : cd_off + 4] == b"PK\x01\x02"
    crc = zlib.crc32(payload) & 0xffffffff
    struct.pack_into("<III", data, cd_off + 16, crc, new_size, new_size)
    Path(dest).write_bytes(data)


def zero_descriptor_variant(dest: str, src: str, archive_comment: bytes = b"") -> None:
    data = bytearray(Path(src).read_bytes())
    lfh_off = data.find(b"PK\x03\x04")
    assert lfh_off != -1
    fn_len = struct.unpack_from("<H", data, lfh_off + 26)[0]
    extra_len = struct.unpack_from("<H", data, lfh_off + 28)[0]
    payload_off = lfh_off + 30 + fn_len + extra_len
    dd_off = data.find(b"PK\x07\x08", payload_off)
    assert dd_off != -1
    struct.pack_into("<III", data, dd_off + 4, 0, 0, 0)
    eocd = data.rfind(b"PK\x05\x06")
    assert eocd != -1
    cd_off = struct.unpack_from("<I", data, eocd + 16)[0]
    struct.pack_into("<III", data, cd_off + 16, 0, 0, 0)
    # EOCD comment always occupies the tail; replace everything after offset 22.
    data[eocd + 22 :] = archive_comment
    struct.pack_into("<H", data, eocd + 20, len(archive_comment))
    Path(dest).write_bytes(data)


def strip_descriptor_signature(dest: str, src: str) -> None:
    data = bytearray(Path(src).read_bytes())
    lfh_off = data.find(b"PK\x03\x04")
    assert lfh_off != -1
    fn_len = struct.unpack_from("<H", data, lfh_off + 26)[0]
    extra_len = struct.unpack_from("<H", data, lfh_off + 28)[0]
    payload_off = lfh_off + 30 + fn_len + extra_len
    dd_off = data.find(b"PK\x07\x08", payload_off)
    assert dd_off != -1
    data[dd_off : dd_off + 4] = b"\x00\x00\x00\x00"
    Path(dest).write_bytes(data)


def zero_central_directory_sizes(dest: str, src: str) -> None:
    data = bytearray(Path(src).read_bytes())
    eocd = data.rfind(b"PK\x05\x06")
    assert eocd != -1
    cd_off = struct.unpack_from("<I", data, eocd + 16)[0]
    assert data[cd_off : cd_off + 4] == b"PK\x01\x02"
    struct.pack_into("<III", data, cd_off + 16, 0, 0, 0)
    Path(dest).write_bytes(data)


def patch_member_name_same_len(dest: str, src: str, old: bytes, new: bytes) -> None:
    assert len(old) == len(new)
    data = bytearray(Path(src).read_bytes())
    lfh_off = data.find(b"PK\x03\x04")
    assert lfh_off != -1
    fn_len = struct.unpack_from("<H", data, lfh_off + 26)[0]
    name_off = lfh_off + 30
    assert data[name_off : name_off + fn_len] == old
    data[name_off : name_off + fn_len] = new
    eocd = data.rfind(b"PK\x05\x06")
    assert eocd != -1
    cd_off = struct.unpack_from("<I", data, eocd + 16)[0]
    assert data[cd_off : cd_off + 4] == b"PK\x01\x02"
    cd_fn_len = struct.unpack_from("<H", data, cd_off + 28)[0]
    cd_name_off = cd_off + 46
    assert data[cd_name_off : cd_name_off + cd_fn_len] == old
    data[cd_name_off : cd_name_off + cd_fn_len] = new
    Path(dest).write_bytes(data)


def patch_cd_external_attr(dest: str, src: str, external_attr: int) -> None:
    data = bytearray(Path(src).read_bytes())
    eocd = data.rfind(b"PK\x05\x06")
    assert eocd != -1
    cd_off = struct.unpack_from("<I", data, eocd + 16)[0]
    assert data[cd_off : cd_off + 4] == b"PK\x01\x02"
    struct.pack_into("<I", data, cd_off + 38, external_attr)
    Path(dest).write_bytes(data)


def clear_data_descriptor_flag(dest: str, src: str) -> None:
    # Only clears the LFH flag; leaves the data descriptor and CD intact to
    # create a mismatch between the flag and the actual descriptor presence.
    data = bytearray(Path(src).read_bytes())
    lfh_off = data.find(b"PK\x03\x04")
    assert lfh_off != -1
    flags = struct.unpack_from("<H", data, lfh_off + 6)[0]
    struct.pack_into("<H", data, lfh_off + 6, flags & ~(1 << 3))
    Path(dest).write_bytes(data)


def clear_flag_and_zero_cd_sizes(dest: str, src: str) -> None:
    data = bytearray(Path(src).read_bytes())
    lfh_off = data.find(b"PK\x03\x04")
    assert lfh_off != -1
    flags = struct.unpack_from("<H", data, lfh_off + 6)[0]
    struct.pack_into("<H", data, lfh_off + 6, flags & ~(1 << 3))
    eocd = data.rfind(b"PK\x05\x06")
    assert eocd != -1
    cd_off = struct.unpack_from("<I", data, eocd + 16)[0]
    assert data[cd_off : cd_off + 4] == b"PK\x01\x02"
    struct.pack_into("<III", data, cd_off + 16, 0, 0, 0)
    Path(dest).write_bytes(data)

with zipfile.ZipFile("accept/store.zip", "w") as z:
    z.writestr(zipfile.ZipInfo("foo"), b"abcdefgh", compress_type=0)

for n in range(0, 8):
    truncate_cd_size(f"iffy/store_cdsize_{n}.zip", "accept/store.zip", n)

with zipfile.ZipFile("accept/deflate.zip", "w") as z:
    z.writestr(zipfile.ZipInfo("foo"), b"abcdefgh", compress_type=8)

with zipfile.ZipFile("accept/subdir.zip", "w") as z:
    z.mkdir("foo")
    z.writestr(zipfile.ZipInfo("foo/bar"), b"abcdefgh", compress_type=0)

with zipfile.ZipFile("malicious/trailing_slash_payload.zip", "w") as z:
    z.writestr(zipfile.ZipInfo("foo/"), b"payload", compress_type=0)

with zipfile.ZipFile("malicious/trailing_slash_name.zip", "w") as z:
    z.writestr(zipfile.ZipInfo("fooX"), b"payload", compress_type=0)

patch_member_name_same_len("malicious/trailing_slash_name.zip", "malicious/trailing_slash_name.zip", b"fooX", b"foo/")

with zipfile.ZipFile("iffy/trailing_slash_attr_mismatch.zip", "w") as z:
    z.writestr(zipfile.ZipInfo("foo/"), b"payload", compress_type=0)

patch_cd_external_attr("iffy/trailing_slash_attr_mismatch.zip", "iffy/trailing_slash_attr_mismatch.zip", 0o100644 << 16)

with zipfile.ZipFile("iffy/nosubdir.zip", "w") as z:
    z.writestr(zipfile.ZipInfo("foo/bar"), b"abcdefgh", compress_type=0)

with zipfile.ZipFile("accept/comment.zip", "w") as z:
    z.comment = b"hello"
    z.writestr(zipfile.ZipInfo("foo"), b"abcdefgh", compress_type=0)

prefix_copy("iffy/prefix_comment.zip", "accept/comment.zip")
truncate_cd_size("iffy/comment_cdsize_0.zip", "accept/comment.zip", 0)
truncate_cd_size("iffy/comment_cdsize_3.zip", "accept/comment.zip", 3)

with zipfile.ZipFile("iffy/extra3byte.zip", "w") as z:
    zi = zipfile.ZipInfo("foo")
    zi.extra = b"   "
    z.writestr(zi, b"abcdefgh", compress_type=0)

with zipfile.ZipFile("iffy/8bitcomment.zip", "w") as z:
    z.comment = b"\x50\x4b\x05\x06\x00\x00\x00\xff\xff" + b"\x00" * 100
    z.writestr(zipfile.ZipInfo("foo"), b"abcdefgh", compress_type=0)

with open("iffy/suffix_not_comment.zip", "wb") as f:
    with zipfile.ZipFile(f, "w") as z:
        z.writestr(zipfile.ZipInfo("foo"), b"abcdefgh", compress_type=0)
    f.write(b'    ')

prefix_copy("iffy/prefix_data_descriptor.zip", "accept/data_descriptor.zip")
prefix_copy("iffy/prefix_data_descriptor_zip64.zip", "accept/data_descriptor_zip64.zip")
prefix_copy("iffy/prefix_deflate.zip", "accept/deflate.zip")
prefix_copy("iffy/prefix_normal_deflate.zip", "accept/normal_deflate.zip")
prefix_copy("iffy/prefix_normal_deflate_zip64_extra.zip", "accept/normal_deflate_zip64_extra.zip")
prefix_copy("iffy/prefix_store.zip", "accept/store.zip")
prefix_copy("iffy/prefix_subdir.zip", "accept/subdir.zip")
prefix_copy("iffy/prefix_crc_collision_two_nonempty.zip", "iffy/crc_collision_two_nonempty.zip")
prefix_copy("iffy/prefix_non_ascii_original_name.zip", "iffy/non_ascii_original_name.zip")
prefix_copy("iffy/prefix_zip64_eocd.zip", "accept/zip64_eocd.zip")

zero_descriptor_variant("iffy/data_descriptor_zero.zip", "accept/data_descriptor.zip")
zero_descriptor_variant("iffy/data_descriptor_zero_cmt_a.zip", "accept/data_descriptor.zip", b"a")
zero_descriptor_variant("iffy/data_descriptor_zero_cmt_hello.zip", "accept/data_descriptor.zip", b"hello")
zero_descriptor_variant("iffy/data_descriptor_zero_cmt_warehouse.zip", "accept/data_descriptor.zip", b"warehouse")
zero_descriptor_variant("iffy/data_descriptor_zero_cmt_packets.zip", "accept/data_descriptor.zip", b"packets")
zero_descriptor_variant("iffy/data_descriptor_zero_cmt_abc123.zip", "accept/data_descriptor.zip", b"abc123")
zero_descriptor_variant("iffy/data_descriptor_zero_cmt_0.zip", "accept/data_descriptor.zip", b"0")
zero_descriptor_variant("iffy/data_descriptor_zero_cmt_zz.zip", "accept/data_descriptor.zip", b"zz")
zero_descriptor_variant("iffy/data_descriptor_zero_cmt_foo.zip", "accept/data_descriptor.zip", b"foo")
zero_descriptor_variant("iffy/data_descriptor_zero_cmt_comment.zip", "accept/data_descriptor.zip", b"comment")
zero_descriptor_variant("iffy/data_descriptor_zero_cmt_meta.zip", "accept/data_descriptor.zip", b"meta")
strip_descriptor_signature("iffy/data_descriptor_no_sig.zip", "accept/data_descriptor.zip")
zero_central_directory_sizes("iffy/data_descriptor_cd_zero.zip", "accept/data_descriptor.zip")
clear_data_descriptor_flag("iffy/data_descriptor_flag_off.zip", "accept/data_descriptor.zip")
clear_flag_and_zero_cd_sizes("iffy/data_descriptor_flag_off_cd_zero.zip", "accept/data_descriptor.zip")

with open("malicious/short_usize.zip", "w+b") as f:
    with zipfile.ZipFile(f, "w") as z:
        z.writestr(zipfile.ZipInfo("file"), A+B, compress_type=8)

    data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_DEFAULT)

    fn1 = data.find(b"file")
    fn2 = data.find(b"file", fn1+1)

    data[fn1-0x8:fn1-0x8+4] = struct.pack("<L", len(A))
    data[fn2-0x16:fn2-0x16+4] = struct.pack("<L", len(A))

    # Could also change the crc, but A and A+B have the same
    # crc = struct.pack("<L", zlib.crc32(b"hello\n"))
    # data[fn1-0x10:fn1-0x10+4] = crc
    # data[fn2-0x1e:fn2-0x1e+4] = crc

with open("malicious/short_usize_zip64.zip", "w+b") as f:
    with zipfile.ZipFile(f, "w", compression=zipfile.ZIP_DEFLATED) as z:
        with z.open(zipfile.ZipInfo("file"), "w", force_zip64=True) as zf:
            zf.write(A+B)
        z.filelist[0].file_size = 0xfefefefefefefefe

    data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_DEFAULT)

    # lfh sizes
    x1 = data.find(b"\xff\xff\xff\xff\xff\xff\xff\xff")
    x2 = data.find(b"\xff\xff\xff\xff\xff\xff\xff\xff", x1+8)
    assert x1 != -1
    assert x2 != -1

    z1 = data.find(b"\x01\x00\x10\x00") + 4
    z2 = data.find(b"\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe")

    (usize, csize) = struct.unpack("<QQ", data[z1:z1+16])

    data[x1:x1+8] = struct.pack("<LL", csize, len(A))
    data[x2:x2+8] = struct.pack("<LL", csize, len(A))
    data[z1:z1+16] = struct.pack("<QQ", csize, len(A+B))
    data[z2:z2+16] = struct.pack("<QQ", csize, len(A+B))

with zipfile.ZipFile("malicious/second_unicode_extra.zip", "w") as z:
    name1 = "original"
    name2 = "first-unicode-extra"
    name3 = "second-unicode-extra"

    zi = zipfile.ZipInfo(name1)
    zi.extra = b"".join([
        struct.pack("<HHBL", 0x7075, len(name2) + 5, 1, zlib.crc32(name1.encode())),
        name2.encode(),
        struct.pack("<HHBL", 0x7075, len(name3) + 5, 1, zlib.crc32(name1.encode())),
        name3.encode(),
    ])
    with z.open(zi, "w") as zf:
        zf.write(b"anything\n")

with zipfile.ZipFile("malicious/unicode_extra_chain.zip", "w") as z:
    name1 = "original"
    name2 = "first-unicode-extra"
    name3 = "ignoreme"
    name4 = "reset-unicode-extra"

    zi = zipfile.ZipInfo(name1)
    zi.extra = b"".join([
        struct.pack("<HHBL", 0x7075, len(name2) + 5, 1, zlib.crc32(name1.encode())),
        name2.encode(),
        # This one doesn't match, and causes info-zip to stop looking
        struct.pack("<HHBL", 0x7075, len(name3) + 5, 1, 4),
        name3.encode(),
        struct.pack("<HHBL", 0x7075, len(name4) + 5, 1, zlib.crc32(name1.encode())),
        name4.encode(),
    ])
    with z.open(zi, "w") as zf:
        zf.write(b"anything\n")

with BytesIO() as b:
    with zipfile.ZipFile(b, "w") as z:
        z.writestr(zipfile.ZipInfo("fileb"), b"B")
    t1 = b.getvalue()

with BytesIO() as b:
    with zipfile.ZipFile(b, "w") as z:
        z.writestr(zipfile.ZipInfo("filea"), b"A")
    t2 = b.getvalue()

with open("malicious/zipinzip.zip", "wb") as f:
    f.write(t1[:-2])
    f.write(struct.pack("<H", len(t2)))
    f.write(t2)

# CRC32 of empty is 0x00000000; this 8-byte sequence also has CRC32=0.
_nonempty_crc0 = bytes.fromhex('d00dfacecb199ef0')
assert zlib.crc32(_nonempty_crc0) == 0

# iffy: two members with the same CRC32 — one empty, one not
with zipfile.ZipFile("iffy/crc_collision_empty_nonempty.zip", "w") as z:
    z.writestr(zipfile.ZipInfo("empty"), b"")
    z.writestr(zipfile.ZipInfo("nonempty"), _nonempty_crc0)

# iffy: two non-empty members of different sizes with the same CRC32
_A = b'abc'
_B = b'abc\xe4\x50\x2c\x59'
assert zlib.crc32(_A) == zlib.crc32(_B)
assert len(_A) != len(_B)
with zipfile.ZipFile("iffy/crc_collision_two_nonempty.zip", "w") as z:
    z.writestr(zipfile.ZipInfo("short"), _A)
    z.writestr(zipfile.ZipInfo("long"), _B)

# iffy: single non-empty member whose CRC32 equals that of the empty file (0)
with zipfile.ZipFile("iffy/crc_zero_nonempty.zip", "w") as z:
    z.writestr(zipfile.ZipInfo("file"), _nonempty_crc0)
