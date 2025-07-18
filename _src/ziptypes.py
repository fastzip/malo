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
    mtime: int = 0 # TODO is this 1980
    mdate: int = 0
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
    mtime: int = 0
    mdate: int = 0
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
