"""
zip/construct.py -- ZIP structure types and a DSL for hand-crafting zip files.

This module provides two things: frozen dataclasses with pack() methods for
each zip record type (LocalFileHeader, CentralDirectoryHeader, EOCD,
Zip64EOCD, Zip64EOCDLocator), and compile(), a small assembler DSL that
handles offsets and forward references for constructing malformed zip files.

DSL reference
-------------

Commands are one per line.  Comments (#) ignore the rest of the line.  Most
args and strings cannot contain spaces or '#', but their prefixes and escape
sequences otherwise behave as in Python.

pad N
    Emit N copies of a placeholder byte.

bit / byte
    Switch to the bitstream language from deflate/asm.py for constructing
    deflate streams by hand.  Byte values are hex.  The mode is sticky for the
    rest of the line.  sync emits zero bits until byte-aligned.

    bit 100 sync byte 0f f0 ff 0

mark NAME
    Record the current byte offset under NAME.  References to marks may be
    forward references; the compiler reruns until all references resolve.
    Using a forward-referenced value to change a length is unlikely to work.

    lfh csize=b-a
    mark a
    deflate b"foo"
    mark b

short / long / quad
    Emit 2/4/8-byte little-endian values.  Plain numbers are hex.  Values
    starting with = are evaluated as Python expressions (decimal literals).

    mark a
    short 0
    mark b
    short =b-a+1 =len(b"foo")

deflate BYTES
    Emit a standard zlib deflate stream for the given byte literal.

crc32 BYTES
    Emit the 4-byte little-endian CRC-32 of the given byte literal.

Structure commands
------------------
All take key=val pairs where val is a Python expression that may reference
marks and builtins.

lfh [key=val ...]       Local File Header
cd  [key=val ...]       Central Directory Entry
z64eocd [key=val ...]   Zip64 End of Central Directory
z64loc  [key=val ...]   Zip64 End of Central Directory Locator
eocd    [key=val ...]   End of Central Directory
"""

import os
import struct
from dataclasses import dataclass
from typing import IO, List, Optional, Sequence, Tuple, TYPE_CHECKING


LOCAL_FILE_HEADER_SIGNATURE = 0x04034B50
LOCAL_FILE_HEADER_FORMAT = "<LHHHHHLLLHH"


@dataclass(frozen=True)
class LocalFileHeader:
    # Section 4.3.7 of APPNOTE.TXT
    signature: int = LOCAL_FILE_HEADER_SIGNATURE
    version_needed: int = 20
    flags: int  = 0
    method: int = 0
    mtime: int = 0       # 00:00:00
    mdate: int = 0x21   # 1980-01-01 (DOS epoch)
    crc32: int = 0
    csize: int = 0
    usize: int = 0
    filename_length: Optional[int] = None
    extra_length: int = 0

    filename: bytes = b"fixme"

    def __post_init__(self):
        if self.filename_length is None:
            object.__setattr__(self, "filename_length", len(self.filename))

    def pack(self) -> bytes:
        return struct.pack(
                LOCAL_FILE_HEADER_FORMAT,
                self.signature,
                self.version_needed,
                self.flags,
                self.method,
                self.mtime,
                self.mdate,
                self.crc32,
                self.csize,
                self.usize,
                self.filename_length,
                self.extra_length,
            ) + self.filename


CENTRAL_DIRECTORY_FORMAT = "<LHHHHHHLLLHHHHHLL"
CENTRAL_DIRECTORY_SIGNATURE = 0x02014B50


@dataclass(frozen=True)
class CentralDirectoryHeader:
    # Section 4.3.12 of APPNOTE.TXT
    signature: int = CENTRAL_DIRECTORY_SIGNATURE
    version_made_by: int = 20
    version_needed: int = 20
    flags: int = 0
    method: int = 0
    mtime: int = 0       # 00:00:00
    mdate: int = 0x21   # 1980-01-01 (DOS epoch)
    crc32: int = 0
    csize: int = 0
    usize: int = 0
    filename_length: Optional[int] = None
    extra_length: int = 0
    comment_length: int = 0

    disk_start: int = 0
    internal_attributes: int = 0
    external_attributes: int = 0
    header_offset: int = 0

    filename: bytes = b"fixme"

    def __post_init__(self):
        if self.filename_length is None:
            object.__setattr__(self, "filename_length", len(self.filename))

    def pack(self) -> bytes:
        return struct.pack(
                CENTRAL_DIRECTORY_FORMAT,
                self.signature,
                self.version_made_by,
                self.version_needed,
                self.flags,
                self.method,
                self.mtime,
                self.mdate,
                self.crc32,
                self.csize,
                self.usize,
                self.filename_length,
                self.extra_length,
                self.comment_length,
                self.disk_start,
                self.internal_attributes,
                self.external_attributes,
                self.header_offset,
            ) + self.filename


ZIP64_EOCD_FORMAT = "<LQHHLLQQQQ"
ZIP64_EOCD_SIGNATURE = 0x06064B50


@dataclass(frozen=True)
class Zip64EOCD:
    signature: int = ZIP64_EOCD_SIGNATURE
    size: Optional[int] = None
    version_made_by: int = 20
    version_needed: int = 20
    disk_num: int = 0
    disk_with_start: int = 0
    num_entries_this_disk: int = 0
    num_entries_total: int = 0
    size_of_cd: int = 0
    offset_start: int = 0
    extensible_data: bytes = b""

    def __post_init__(self):
        if self.size is None:
            object.__setattr__(self, "size", struct.calcsize(ZIP64_EOCD_FORMAT) + len(self.extensible_data) - 12)

    def pack(self) -> bytes:
        return struct.pack(
                ZIP64_EOCD_FORMAT,
                self.signature,
                self.size,
                self.version_made_by,
                self.version_needed,
                self.disk_num,
                self.disk_with_start,
                self.num_entries_this_disk,
                self.num_entries_total,
                self.size_of_cd,
                self.offset_start,
            ) + self.extensible_data


ZIP64_EOCD_LOCATOR_FORMAT = "<LLQL"
ZIP64_EOCD_LOCATOR_SIGNATURE = 0x07064B50


@dataclass(frozen=True)
class Zip64EOCDLocator:
    signature: int = ZIP64_EOCD_LOCATOR_SIGNATURE
    disk_with_start: int = 0
    relative_offset: int = 0
    total_disks: int = 1

    def pack(self) -> bytes:
        return struct.pack(
            ZIP64_EOCD_LOCATOR_FORMAT,
            self.signature,
            self.disk_with_start,
            self.relative_offset,
            self.total_disks,
        )


EOCD_FORMAT = "<LHHHHLLH"
EOCD_SIGNATURE = 0x06054B50


@dataclass(frozen=True)
class EOCD:
    signature: int = EOCD_SIGNATURE
    disk_num: int = 0
    disk_with_start: int = 0
    num_entries_this_disk: int = 0
    num_entries_total: int = 0
    size: int = 0
    offset_start: int = 0
    comment_length: Optional[int] = None
    comment: bytes = b""

    def __post_init__(self):
        if self.comment_length is None:
            object.__setattr__(self, "comment_length", len(self.comment))

    def pack(self) -> bytes:
        return struct.pack(
                EOCD_FORMAT,
                self.signature,
                self.disk_num,
                self.disk_with_start,
                self.num_entries_this_disk,
                self.num_entries_total,
                self.size,
                self.offset_start,
                self.comment_length,
            ) + self.comment


import ast
import sys
import re
import zlib
from io import BytesIO

from malo.deflate.asm import compile as bit_compile

# TODO rewind?
# TODO insert mode?
# TODO num x count

LINE_RE = re.compile(
    r'((?P<cmd>\w+)[ \t]+(?P<rest>.*))?(?P<comment>[ \t]*#.*)?\n'
)

def name(tok):
    return [k for k, v in tok.groupdict().items() if v is not None][0]

def restofline(it):
    line = ""
    while not line.endswith("\n"):
        if line:
            line += " "
        line += next(it).group(0)
    return line

FORMATS = {
    "short": "<H",
    "long": "<L",
    "quad": "<Q",
}

STRUCTURES = {
    "eocd": EOCD,
    "z64loc": Zip64EOCDLocator,
    "z64eocd": Zip64EOCD,
    "cd": CentralDirectoryHeader,
    "lfh": LocalFileHeader,
}

def compile(s, verbose=False):
    buf = BytesIO()
    env = {}

    def h(expr):
        if expr.startswith("="):
            expr = expr[1:].replace(".", "cur")
            env["cur"] = buf.tell()
            try:
                return eval(expr, env, env)
            except NameError as e:
                nonlocal forward_reference
                forward_reference = True
                return 0
        else:
            return int(expr, 16)

    def d(tmp):
        args = {}
        for arg in tmp.split():
            k, eq, v = arg.partition("=")
            if v.isdigit():
                args[k] = h(v)
            else:
                args[k] = h(eq + v)
        return args


    for _ in range(5):
        buf.seek(0, 0)
        buf.truncate()

        forward_reference = False
        for line in LINE_RE.finditer(s):
            n = line.group("cmd")
            c = line.group("comment")
            if not n and not c:
                continue

            if verbose:
                print("> " + line.group(0).rstrip())

            if not n:
                continue

            start_pos = buf.tell()
            if n in ("bit", "byte"):
                buf.write(bytes(bit_compile(n + " " + line.group("rest"))))
            elif n == "pad":
                buf.write(b"X" * h(line.group("rest")))
            elif n in ("short", "long", "quad"):
                f = FORMATS[n]
                for t in line.group("rest").split():
                    buf.write(struct.pack(f, h(t)))
            elif n == "deflate":
                arg = line.group("rest")
                val = ast.literal_eval(arg)
                buf.write(zlib.compress(val, -1, -15))
            elif n == "crc32":
                arg = line.group("rest")
                val = ast.literal_eval(arg)
                buf.write(struct.pack("<L", zlib.crc32(val)))
            elif n in STRUCTURES:
                args = d(line.group("rest"))
                e = STRUCTURES[n](**args)
                buf.write(e.pack())
            elif n == "mark":
                key = line.group("rest")
                env[key] = buf.tell()
                continue
            elif n == "assert":
                a, b = line.group("rest").split()
                av = h(a)
                bv = h(b)
                if not forward_reference and av != bv:
                    raise AssertionError(f"{av!r} != {bv!r}")
                continue
            else:
                raise NotImplementedError(n)

            if verbose:
                print("  | " + " ".join("%02x" % c for c in buf.getvalue()[start_pos:]), file=sys.stderr)

        if not forward_reference:
            return buf.getvalue()

    raise Exception("Could not complete forward references after some tries")

if __name__ == "__main__":
    compile(verbose=True, s="""\
mark x
# comment
byte 1 2 3
assert =.-x 3
long =.-x
mark n

lfh filename=b"z"
cd filename=b"z"
eocd num_entries_this_disk=5 comment=b"xyz"
z64eocd num_entries_this_disk=5
z64loc relative_offset=n
deflate b"abc"
""")
