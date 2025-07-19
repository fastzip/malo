import mmap
import struct
import zipfile
import zlib
from io import BytesIO

A = b"# benign\n"
B = b"print('malicious')\n# 12323013111123311000\n"

with zipfile.ZipFile("accept/store.zip", "w") as z:
    z.writestr(zipfile.ZipInfo("foo"), b"abcdefgh", compress_type=0)

with zipfile.ZipFile("accept/deflate.zip", "w") as z:
    z.writestr(zipfile.ZipInfo("foo"), b"abcdefgh", compress_type=8)

with zipfile.ZipFile("accept/subdir.zip", "w") as z:
    z.mkdir("foo")
    z.writestr(zipfile.ZipInfo("foo/bar"), b"abcdefgh", compress_type=0)

with zipfile.ZipFile("iffy/nosubdir.zip", "w") as z:
    z.writestr(zipfile.ZipInfo("foo/bar"), b"abcdefgh", compress_type=0)

with zipfile.ZipFile("iffy/prefix.zip", "w") as z:
    z.fp.write(b'    ')
    z.writestr(zipfile.ZipInfo("foo"), b"abcdefgh", compress_type=0)

with zipfile.ZipFile("accept/comment.zip", "w") as z:
    z.comment = b"hello"
    z.writestr(zipfile.ZipInfo("foo"), b"abcdefgh", compress_type=0)

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

    # 
    z1 = data.find(b"\x01\x00\x10\x00") + 4
    z2 = data.find(b"\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe")

    (usize, csize) = struct.unpack("<QQ", data[z1:z1+16])

    data[x1:x1+8] = struct.pack("<LL", csize, len(A))
    data[x2:x2+8] = struct.pack("<LL", csize, len(A))
    data[z1:z1+16] = struct.pack("<QQ", csize, len(A+B))
    data[z2:z2+16] = struct.pack("<QQ", csize, len(A+B))

    # data[x1:x1+8] = struct.pack("<L", len("hello\n"))
    # data[fn2-0x16:fn2-0x16+4] = struct.pack("<L", len("hello\n"))

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
