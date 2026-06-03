---
hackmd: JiQk3fArTyuggJ3EM_6qdA
---
# ZAR Design Document

# 1 Overview

## 1.1 The Pitch

Almost all popular archive formats suffer from underspecification mixed with complexity, as well as drift over time where features (like utf-8, or 64-bit file sizes) are shoehorned in without an eye to security.

This draft attempts to find a middle ground for a **secure, unambiguous** archive format that is inherenently validatable, streamable, strict from the beginning of its existence, and future-proof.

I call it **ZAR**

> Tim: I know it's hubris to invent a new format -- this is inspired by both [XAR](https://en.wikipedia.org/wiki/Xar_(archiver)) (overall structure) and [NAR](https://nix.dev/manual/nix/2.22/protocols/nix-archive) (deceptively simple) with some ordering and strictness changes that should make it more consistent cross-platform.  Familiarity with those isn't necessary for what follows.

The next section goes into the tenets that are important for this format (with the unstated assumption that ZIP and TAR cannot provide these even in a restricted form)


[2]: It's like XAR but two better.  Apple's, not Facebook's.

# 2 Functional spec

## 2.1 Consistent cross-platform behavior

By restricting filenames slightly and considering names to be case-insensitive by default (as modern import sorters do) we get more consistent cross-platform behavior.  Handling encodings is one of the buggiest pieces of both tar and zip implementations today.

## 2.2 Be self-verifying

Against accidental corruption like spinning disks or cosmic rays, we should be able to verify that a file is self-consistent using only the data contained within -- ideally quickly and (when extracting) with as little done to the filesystem before we know.

This implies stronger checksums, not at the tail where it's easy to ignore, or crc32 which isn't a cryptograph checksum.

## 2.3 Streamable without seeks

Unlike zip's notorious tail-first processing, you should be able to just request the file from the beginning and stop when you have enough to do your job.

In addition to behaving well over HTTP, this also behaves well on Windows where seeks can be slow (on spinning disks).

## 2.4 Unambiguous, wherever possible

As an example, this means not storing mappings-to-mappings, or things like names and offsets multiple places that can disagree.

## 2.5 Strict from the start

Every stage should be able to validate against consistent rules.  This includes a conformance suite, the local archiver verifying, the uploader verifying, the index upload endpoint verifying, and the extractor verifying.  Everyone should know when to reject, and do that by default.  Packers should be the most strict, obeying the robustness principle.

## 2.6 "obvious" spec

Ideally the spec should be written in simple, unambiguous language unencumbered by "compatibility" with buggy encoders of the past. Whoever publishes the spec should care about keeping it up to date and closing any holes, before people go implementing it multiple ways.  Don't be afraid of revving and applying new validation to existing files retroactively if it's a security issue.

## 2.7 Limit the value of confusion

...with as little done to the filesystem before knowing.  As an example, if there were a differential that got the stride wrong for a combined `name+contents,name+contents` stream, there might be entire wrong names or contents extracted.  A safer differential (if it can't be prevented entirely) would be to let two files swap contents.

## 2.8 Zstd compression

This is kind of table-stakes for any new format, but also limits the choices we have to support:

* You can trivially make "stored" blocks by hand
* You can use compression level 0 which is competitive with deflate
* You can compress multithreaded (on larger files, where it matters more), allowing higher compression levels.

Exact wins TBD (28% on django, 8MB wheel; 55% on tf-nightly, 233MB wheel) if people are patient/parallel enough to use level 19 for the one-time cost at release. That pays dividends at download and extract time, potentially millions of times.

## 3 File format

```
start      size  what
-----      ---   ----
0          88    fixed header, with magic, sizes (a and b) and sha256 checksums
    0      4     "B\0RE" magic
    4      4     "zstd"  compression
    8      8     <a>     compressed size of manifest
    16     32    ...     manifest compressed checksum
    48     8     <b>     compressed size of contents
    56     32    ...     contents compressed checksum
88         a     "manifest" zstd stream (one or more frames)
88+a       4     padding (ff ff ff ff)
88+a+4     b     "contents" zstd stream
```

## 3.1 Fixed Header

This starts with the magic and compression in order to support future updates.  You MUST check both, and fail with an error listing the mismatched value if they're not what you support.

Integers are little-endian (size of compressed data), and checksums are binary SHA-256 (of the compressed data).

## 3.2 Manifest stream

This UTF-8 (see section 4) JSON, zstd-compressed.  For avoidance of doubt, "JSON" _does not_ allow comments, trailing commas, etc and _does_ allow string escapes.

The manifest MAY span multiple zstd frames; skippable frames are permitted between them.  The combined compressed bytes MUST match the declared size and checksum.

## 3.3 Padding

Exactly 4 bytes of `0xff` (`ff ff ff ff`) appear between the manifest and contents sections.  Parsers MUST verify all four bytes.  Since `0xff` is not a valid zstd frame magic byte, a decoder that miscounts the manifest length will fail loudly here rather than silently misparse the contents.

## 3.4 Contents stream

Zstd data of the file contents concatenated.  This MAY be multiple frames, and MUST be at least one unless the total uncompressed file contents are empty, in which case the contents section MAY be empty.

Each frame MUST include complete files, and MAY include more than one.

You SHOULD avoid emitting empty frames except in the entirely-empty-bytes case.

## 3.5 Packing requires buffering

ZAR does not lend itself to single-pass streaming compression.  The fixed header must contain `manifest_csize`, `contents_csize`, and both SHA-256 checksums -- none of which are known until the corresponding section has been fully compressed.  A packer must therefore buffer or seek:

1. Compress the manifest into memory (it is small).
2. Compress the contents to a temporary file or buffer.
3. Compute sizes and checksums, write the 88-byte header, then stream the compressed sections to the final output.

This is the same tradeoff as XAR, which also places a compressed TOC before the compressed data.  It is the opposite tradeoff from gzip or zstd streaming, where the compressor can write output as input arrives.  The upside is that readers never need to seek -- the metadata needed to validate or index the archive arrives in the first read, before any file data.

# 4 Member names

The point of this format is not to simply store data, it is for the eventual goal of extracting to a real file system somewhere. there is a lot of variety in how file names get normalized across OSes and the goal is to allow what works in most (so we dont create knowingly or expectedly unextractable archives) while reducing the risk of confusing an extractor.

Many formats store filenames as a series of bytes, or allow the user to specify an encoding, but that has been the source of many differentials (especially where the name can exist more than one place).  This format encodes names as valid UTF-8, with few additional restrictions except that you can't have to members plausibly named the same.

See https://hackmd.io/MeNFtl5qRWi2HhTKdhis1A for that separate spec.


# 5 Safe Extraction

## 5.1 Extraction order

Process manifest entries in this order:

1. **Directories** -- create all dirs first, parents before children (the manifest ordering guarantees this).
2. **Files** -- write file contents.
3. **Symlinks** -- create symlinks last, after all their targets exist.

## 5.2 Extracting to a fresh directory

Use create-new-only semantics so a duplicate or colliding name is a hard error rather than a silent overwrite.

**Linux** -- `openat2(2)` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS` atomically prevents escape through any intermediate path component:

```python
import ctypes, os

SYS_openat2         = 437   # x86-64; see <sys/syscall.h> for other arches
RESOLVE_BENEATH     = 0x08
RESOLVE_NO_SYMLINKS = 0x04

class _OpenHow(ctypes.Structure):
    _fields_ = [("flags",   ctypes.c_uint64),
                ("mode",    ctypes.c_uint64),
                ("resolve", ctypes.c_uint64)]

_libc = ctypes.CDLL(None, use_errno=True)

def safe_create(dirfd: int, relpath: str, mode: int = 0o666) -> int:
    how = _OpenHow(
        flags   = os.O_CREAT | os.O_EXCL | os.O_WRONLY,
        mode    = mode,
        resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS,
    )
    fd = _libc.syscall(SYS_openat2, dirfd, relpath.encode(),
                       ctypes.byref(how), ctypes.sizeof(how))
    if fd < 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()), relpath)
    return fd
```

**Windows** -- `CREATE_NEW` gives create-or-fail atomicity (equivalent to `O_CREAT | O_EXCL`).

`FILE_FLAG_OPEN_REPARSE_POINT` only prevents following a reparse point on the *final* path component; it does nothing for intermediate components.  The Win32 API has no equivalent flag for that. Use the Nt API instead: `NtCreateFile` with `OBJ_DONT_REPARSE` (0x1000) in `OBJECT_ATTRIBUTES.Attributes`, which prevents traversal of any reparse point anywhere in the path.  Walking components and calling `GetFileAttributesW` to check `FILE_ATTRIBUTE_REPARSE_POINT` before descending also works, but has a race window that is only exploitable by someone who already has write access to the extraction directory (in which case they can cause harm through other means anyway).

To refuse to open a symlink as a regular file on the final component: open with `FILE_FLAG_OPEN_REPARSE_POINT`, then call `GetFileInformationByHandleEx` with `FileAttributeTagInfo` and reject if `ReparseTag == IO_REPARSE_TAG_SYMLINK` (0xA000000C).

**Detecting Windows reserved device names** -- reject any path component matching (case-insensitive):

```
^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(\..*)?$
```

This set is fully enumerated and stable; Microsoft has not added new reserved names in decades.  The definitive runtime check is to open the path and test `GetFileType(handle) == FILE_TYPE_CHAR`, but the regex on each component avoids touching the filesystem and is sufficient for well-formed paths.

**Long path support on Windows** -- By default, Windows limits paths to MAX_PATH (260 characters).  Long-path support (paths up to ~32767 characters) requires both a registry opt-in (`LongPathsEnabled`) and an application manifest declaring `longPathAware`.  Python 3.6+ ships with a manifest that enables this, so Python extractors work as long as the registry key is set.  Paths exceeding MAX_PATH on systems without the opt-in will fail with `ERROR_PATH_NOT_FOUND` or similar, even if the individual components are short.

**Symlink support on Windows** -- Creating symlinks via `CreateSymbolicLinkW` requires Developer Mode (Windows 10 1703+) or elevation; extraction of archives containing symlinks will fail on standard Windows installs without one of those.  Git for Windows enables Developer Mode as part of its installer and configures the necessary privilege, which is why Git users rarely encounter this limitation but others do.  Directory junctions (`IO_REPARSE_TAG_MOUNT_POINT`) are not a substitute: they cannot target files, cannot use relative paths, and require elevation to create.

## 5.3 Path length limits

ZAR restricts filenames to shift common hazards left (no trailing dots, no reserved components, etc.) but cannot guarantee that every valid archive path will be accepted by every filesystem.  The extraction directory itself may have a long prefix that pushes an otherwise-reasonable member path over the OS limit (`PATH_MAX` on Linux, typically 4096 bytes; MAX_PATH on Windows without the long-path opt-in).

When a path would exceed the platform limit, **fail the extraction -- do not silently skip the member**.  Skipping produces a silently incomplete extraction with no indication that files are missing.  This applies whether you use `openat2`, plain `open`, or any other file-creation primitive; the failure mode should be a clear error naming the affected path.

## 5.4 Extracting to an existing directory

Out of scope for this spec. Conflict policy depends on the application.

# 6 Smuggling

ZAR does not attempt to prevent an archive from simultaneously being a valid instance of another format (a "turduckeon").  Prevention is not achievable: zstd compressed blocks and uncompressed stored blocks can carry arbitrary byte patterns, so any byte sequence (including another format's magic or structure) can appear inside a conforming ZAR archive.  Rejecting skippable frames would not close this hole; it would merely exclude one specific mechanism while leaving all others open.

Therefore: skippable frames (RFC 8878 magic `50 2a 4d 18`–`5f 2a 4d 18`) are permitted in both the manifest and contents sections.  Parsers MUST skip them silently.  The `manifest_sha256` and `contents_sha256` in the header cover the full respective sections, including any skippable frames.

# 7 Why not...

## 7.1 Use an existing format

We need to make the tools validate as they create, and it's not clear how to make backwards-compatible changes to .whl

## 7.2 Allow specifying compression method

Unnecessary -- zstd is the current winner for reasonable compression speed with good ratio, and is part of stdlib.  If you want STORE, you can get that either literally or just specifying level=0.  If we need to add some not-yet-existing format, we bump bytes [4:8] of the magic

## 7.3 Store dates, if we're not fully reproducible

Dates are not stored because they are not generally useful enough to require.  Most consumers of a built artifact care about its contents, not when each file was last touched.  Omitting dates also leaves open a path toward content-addressable archives: an archive whose output is fully determined by its inputs can be identified by a hash of the archive itself, which is useful for caching and deduplication.

# 8 Decisions to revisit

- whether we want metadata more first-class, rather than just contents -- imagine a third stream in between that is the "read-me-first" one with a fixed-header size
- stronger recommendations about what the optimistic first read should be, so that packers can warn loudly/require escape hatch if metadata doesn't all fit
- come up with what it would look like to make zip "as secure"
- take a firmer stance on the CAS url idea
- think through whether frames [given the manifest] can be unpacked to disk independently
- sorting by extension isn't actually a win in many cases

# 9 Intentional stained-glass-window-in-the-bathroom

- The name itself
- Use of JSON (it's ubiquitous, but has nontrivial string parsing).  I'd rather use bencode (or something more custom/small).
- Mixing the python-specific bits in with the format itself -- this is really fence-sitting
- Recommending str.casefold checking -- this is more restrictive than necessary, and we should be more opinionated/consistent
