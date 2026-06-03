import struct
from dataclasses import dataclass
from typing import Optional

TAR_BLOCK = 512


def _octal(value: int, width: int) -> bytes:
    """Encode value as NUL-terminated octal in a fixed-width field.
    Truncates on overflow; useful for producing malformed fixtures."""
    return ("%0*o" % (width - 1, value)).encode()[:width - 1] + b"\0"


def _checksum(block: bytes) -> int:
    """Unsigned sum treating the 8 checksum bytes (148-155) as spaces."""
    return sum(block[:148]) + 8 * 0x20 + sum(block[156:])


def pad_data(data: bytes) -> bytes:
    r = len(data) % TAR_BLOCK
    return data + (b"\0" * (TAR_BLOCK - r) if r else b"")


def end_of_archive() -> bytes:
    return b"\0" * (TAR_BLOCK * 2)


@dataclass(frozen=True)
class TarHeader:
    # POSIX ustar header -- always packs to exactly 512 bytes.
    # Numeric fields are stored as ASCII octal in pack(); override checksum
    # with an explicit int to produce malformed headers for reject/ fixtures.
    name: bytes = b"file"
    mode: int = 0o644
    uid: int = 0
    gid: int = 0
    size: int = 0
    mtime: int = 0
    checksum: Optional[int] = None  # computed if None
    typeflag: bytes = b"0"          # 0=file, 5=dir, 2=symlink, L=GNU long name
    linkname: bytes = b""
    magic: bytes = b"ustar\x00"     # POSIX; GNU uses b"ustar  " (space+NUL→space+space)
    version: bytes = b"00"          # POSIX; GNU uses b" \x00"
    uname: bytes = b""
    gname: bytes = b""
    devmajor: int = 0
    devminor: int = 0
    prefix: bytes = b""             # POSIX path prefix for names > 100 chars

    def pack(self) -> bytes:
        def p(b: bytes, n: int) -> bytes:
            return b[:n].ljust(n, b"\0")

        block = (
            p(self.name, 100)
            + _octal(self.mode, 8)
            + _octal(self.uid, 8)
            + _octal(self.gid, 8)
            + _octal(self.size, 12)
            + _octal(self.mtime, 12)
            + b"        "           # checksum placeholder (8 spaces)
            + p(self.typeflag, 1)
            + p(self.linkname, 100)
            + p(self.magic, 6)
            + p(self.version, 2)
            + p(self.uname, 32)
            + p(self.gname, 32)
            + _octal(self.devmajor, 8)
            + _octal(self.devminor, 8)
            + p(self.prefix, 155)
            + b"\0" * 12
        )
        assert len(block) == TAR_BLOCK

        cs = self.checksum if self.checksum is not None else _checksum(block)
        # Standard checksum encoding: 6 octal digits + NUL + space = 8 bytes
        cs_field = ("%06o\0 " % cs).encode()
        return block[:148] + cs_field + block[156:]


def gnu_longname(name: bytes) -> bytes:
    """GNU long-name extension: 'L' header block followed by name data block."""
    header = TarHeader(name=b"././@LongLink", typeflag=b"L", size=len(name) + 1)
    return header.pack() + pad_data(name + b"\0")


def gnu_longlink(linkname: bytes) -> bytes:
    """GNU long-linkname extension: 'K' header block followed by linkname data block."""
    header = TarHeader(name=b"././@LongLink", typeflag=b"K", size=len(linkname) + 1)
    return header.pack() + pad_data(linkname + b"\0")
