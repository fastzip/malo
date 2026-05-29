import ctypes
import ctypes.util
import struct
from dataclasses import dataclass
from typing import Optional

ZSTD_MAGIC = 0xFD2FB528
ZSTD_SKIPPABLE_MAGIC_MIN = 0x184D2A50
ZSTD_SKIPPABLE_MAGIC_MAX = 0x184D2A5F

# Load libzstd via ctypes so we call the C API directly rather than going
# through a Python wrapper, keeping fixture generation independent of any
# one wrapper's behavior choices.
_libname = ctypes.util.find_library("zstd")
if _libname:
    _lib = ctypes.CDLL(_libname)
    _lib.ZSTD_compressBound.restype = ctypes.c_size_t
    _lib.ZSTD_compressBound.argtypes = [ctypes.c_size_t]
    _lib.ZSTD_compress.restype = ctypes.c_size_t
    _lib.ZSTD_compress.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_int,
    ]
    _lib.ZSTD_isError.restype = ctypes.c_uint
    _lib.ZSTD_isError.argtypes = [ctypes.c_size_t]
    _lib.ZSTD_createCCtx.restype = ctypes.c_void_p
    _lib.ZSTD_createCCtx.argtypes = []
    _lib.ZSTD_freeCCtx.restype = ctypes.c_size_t
    _lib.ZSTD_freeCCtx.argtypes = [ctypes.c_void_p]
    _lib.ZSTD_compress_usingDict.restype = ctypes.c_size_t
    _lib.ZSTD_compress_usingDict.argtypes = [
        ctypes.c_void_p,                    # ctx
        ctypes.c_void_p, ctypes.c_size_t,  # dst, dstCapacity
        ctypes.c_void_p, ctypes.c_size_t,  # src, srcSize
        ctypes.c_void_p, ctypes.c_size_t,  # dict, dictSize
        ctypes.c_int,                       # compressionLevel
    ]
else:
    _lib = None


def compress(data: bytes, level: int = 3) -> bytes:
    """Produce a complete zstd frame via ZSTD_compress() C API."""
    if _lib is None:
        raise RuntimeError("libzstd not found (install zstd)")
    bound = _lib.ZSTD_compressBound(len(data))
    buf = (ctypes.c_char * bound)()
    n = _lib.ZSTD_compress(buf, bound, data, len(data), level)
    if _lib.ZSTD_isError(n):
        raise RuntimeError(f"ZSTD_compress error code {n}")
    return bytes(buf[:n])


def compress_with_prefix(data: bytes, prefix: bytes, level: int = 3) -> bytes:
    """Compress data using prefix as a raw-content external dictionary.

    The resulting frame has no dict_id field. Its sequences will contain
    back-reference offsets into the prefix region, so a decoder that lacks
    the prefix will encounter offsets exceeding its available history and
    must reject the frame per spec.
    """
    if _lib is None:
        raise RuntimeError("libzstd not found (install zstd)")
    cctx = _lib.ZSTD_createCCtx()
    try:
        bound = _lib.ZSTD_compressBound(len(data))
        buf = (ctypes.c_char * bound)()
        n = _lib.ZSTD_compress_usingDict(
            cctx, buf, bound, data, len(data), prefix, len(prefix), level
        )
        if _lib.ZSTD_isError(n):
            raise RuntimeError(f"ZSTD_compress_usingDict error code {n}")
        return bytes(buf[:n])
    finally:
        _lib.ZSTD_freeCCtx(cctx)


@dataclass(frozen=True)
class ZstdBlockHeader:
    last_block: bool = False
    block_type: int = 0   # 0=Raw_Block, 1=RLE_Block, 2=Compressed_Block, 3=Reserved
    block_size: int = 0

    def pack(self) -> bytes:
        # 3-byte LE: bit0=Last_Block, bits[2:1]=Block_Type, bits[23:3]=Block_Size
        val = (self.block_size << 3) | (self.block_type << 1) | self.last_block
        return val.to_bytes(3, "little")


@dataclass(frozen=True)
class ZstdFrameHeader:
    """
    Manually-constructed zstd frame header (RFC 8878).

    FHD layout:
      bits [7:6]  FCS_Flag         — 0→0/1B content size, 1→2B, 2→4B, 3→8B
      bit  [5]    Single_Segment   — 1 → Window_Descriptor omitted; CS mandatory
      bit  [4]    Unused_Bit       — must be 0 per spec
      bit  [3]    Reserved_Bit     — must be 0 per spec (set to test rejection)
      bit  [2]    Content_Checksum — 1 → 4-byte xxHash64 appended after last block
      bits [1:0]  Dict_ID_Flag     — 0→none, 1→1B, 2→2B, 3→4B dict id

    content_size and dict_id are raw bytes — caller controls encoding.
    window_descriptor is included verbatim when not None (Single_Segment=0).
    """
    magic: int = ZSTD_MAGIC
    fhd: int = 0
    window_descriptor: Optional[int] = None
    dict_id: bytes = b""
    content_size: bytes = b""

    def pack(self) -> bytes:
        out = struct.pack("<IB", self.magic, self.fhd)
        if self.window_descriptor is not None:
            out += bytes([self.window_descriptor & 0xff])
        return out + self.dict_id + self.content_size


@dataclass(frozen=True)
class ZstdSkippableFrame:
    magic: int = ZSTD_SKIPPABLE_MAGIC_MIN  # any value in [MIN, MAX] is valid
    data: bytes = b""

    def pack(self) -> bytes:
        return struct.pack("<II", self.magic, len(self.data)) + self.data


def simple_frame_header(content_size: int, checksum: bool = False) -> ZstdFrameHeader:
    """Single-segment frame header with 8-byte content size field."""
    # FCS_Flag=3 (8B) | Single_Segment=1 | Content_Checksum per arg
    fhd = 0b11100000 | (0b00000100 if checksum else 0)
    return ZstdFrameHeader(fhd=fhd, content_size=struct.pack("<Q", content_size))
