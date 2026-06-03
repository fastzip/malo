---
hackmd: k9TBSD3iQieQBP1Q6d7Dcg
---
# ZAR Spec

## Overall layout

```
[Header: 88 bytes fixed]
[Manifest section: manifest_csize bytes]
[Padding: 4 bytes of 0xff]
[Contents section: contents_csize bytes]
```

Total file size = 88 + manifest_csize + 4 + contents_csize.

---

## Header (88 bytes)

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0 | 4 | **Magic** | `42 00 52 45` (`B\0RE`); byte 1 is format version (currently `\0`) |
| 4 | 4 | **Compression algo** | ASCII name: `"zstd"` |
| 8 | 8 | **manifest_csize** | LE u64, compressed byte length of manifest section |
| 16 | 32 | **manifest_sha256** | SHA-256 of the *compressed* manifest bytes |
| 48 | 8 | **contents_csize** | LE u64, compressed byte length of contents section |
| 56 | 32 | **contents_sha256** | SHA-256 of the *compressed* contents bytes |

> Sizes and SHA-256 targets are *compressed* bytes; SHA-256 fields cover only their respective section, not the padding. Decoders MUST reject archives with an unrecognized version byte. Future revisions that introduce a breaking structural requirement are expected to increment it.

---

## Definitions

### zstd stream

One or more frames per [RFC 8878](https://www.rfc-editor.org/rfc/rfc8878). Frames MUST be independently decodable (no cross-frame back-references), MUST NOT declare a dictionary (not even id 0), and each frame's last block MUST have the `final` bit set. Skippable frames (magic `50 2a 4d 18`–`5f 2a 4d 18`) are permitted anywhere and MUST be silently skipped. The stream MUST consume exactly the declared csize bytes; there MUST be no trailing bytes after the final frame within the section.

On window sizes, RFC 8878 §3.1.1 says:

> For improved interoperability, it's recommended for decoders to support values of Window_Size up to 8 MB and for encoders not to generate frames requiring a Window_Size larger than 8 MB. It's merely a recommendation though, and decoders are free to support higher or lower limits, depending on local limitations.

The `"zstd"` compression identifier in ZAR makes this a hard requirement: frames MUST NOT declare a Window_Size larger than 8 MB. Note that for single-segment frames (`Single_Segment_Flag=1` in the Frame_Header_Descriptor), the zstd spec sets Window_Size equal to Frame_Content_Size, so a single-segment frame larger than 8 MB also violates this rule. If a future revision needs to permit larger windows, it will use a different four-character compression identifier; decoders MUST reject any compression field they do not recognize.

### path string

Valid UTF-8 (no overlong encodings, no surrogates, no invalid bytes), satisfying the [filename validation rules](#filename-validation-rules). See [unicode.md](unicode.md) for normalization and duplicate-name rules.

---

## Manifest section

A **zstd stream** decompressing to a UTF-8 JSON value of the form:

```json
[ dirs, files, symlinks ]
```

Unknown fields on any entry object MUST be rejected. This keeps the format extensible via version bumps rather than by accumulating ignored cruft.

### `dirs` -- array of directory entries

```json
{ "name": "path/to/dir" }
```

- `name` is a **path string**.
- Every directory ancestor that appears in a file path must be listed.
- Deeper dirs must always be listed after their parents.

### `files` -- array of regular-file entries

```json
{
  "name":        "relative/path.txt",
  "usize":       5,
  "sha256":      "2cf24d...",
  "x":           true,
  "frame_start": 14
}
```

| Field | Required | Notes |
|-------|----------|-------|
| `name` | yes | **path string** |
| `usize` | yes | uncompressed byte count |
| `sha256` | yes | lowercase hex SHA-256 of uncompressed content |
| `x` | no | executable bit; if present must be exactly `true` |
| `frame_start` | no | compressed byte offset of the start of a new contents frame |

- `frame_start` absent = this file continues in the same frame as the previous file
- `frame_start` present = a new zstd frame begins at this compressed byte offset within the contents section; this file is the first in that frame
- `frame_start` MUST NOT appear on the first file (it is always implicitly at offset 0)
- `frame_start` MUST coincide with an actual zstd frame boundary; not all frame boundaries need to be declared
- `frame_start` values must be strictly increasing
- `frame_start` must be within `(0, contents_csize)`
- MUST NOT be set on a file immediately following a zero-byte file; since the zero-byte file advances the uncompressed position by nothing, any frame boundary declared here would be indistinguishable from one on the zero-byte file itself, producing an illegal duplicate value

### `symlinks` -- array of symlink entries

```json
{ "name": "link.txt", "target": "hello.txt" }
```

- Target must name an existing regular file or directory within the same archive.
- Symlinks cannot chain (target cannot itself be a symlink).

---

## Padding

Exactly 4 bytes of `0xff` (`ff ff ff ff`) appear between the manifest and contents sections. Parsers MUST verify all four bytes. This acts as a sentinel: `0xff` is not a valid zstd frame magic byte, so a decoder that miscounts the manifest length will fail loudly here rather than silently misparse the contents.

---

## Contents section

A **zstd stream** carrying file contents concatenated in manifest file-list order. Each frame contains one or more complete files; a file's content MUST NOT span a frame boundary. The per-file `sha256` and `usize` in the manifest MUST match the actual decompressed bytes. For avoidance of doubt, the file data appears in the same order as the `files` array in the manifest.

If the total uncompressed file contents are empty, the contents section MAY be empty (`contents_csize=0`), with no zstd frames at all. This includes the case where the manifest has no files, and the case where every file is zero bytes.

---

## Filename validation rules

### `reject/` -- parsers must always reject these

| Rule | Test case |
|---|---|
| No absolute paths (`/foo`) | `filename_absolute` |
| No `..` as a path | `filename_dotdot` |
| No `..` as a path component (`a/../b`) | `filename_dotdot_component` |
| No `.` as a path | `filename_dot` |
| No `.` as a path component | `filename_dot_component` |
| No empty path component (`a//b`) | `filename_empty_component` |
| No trailing dot on a component | `filename_trailing_dot` |
| No trailing space on a component | `filename_trailing_space` |
| No tilde (`~`) | `filename_tilde` |
| No backslash (`\`) | `filename_backslash` |
| No colon (`:`) | `filename_colon` |
| No BOM (U+FEFF) anywhere in path | `filename_bom` |
| No Unicode non-characters (U+FDD0-U+FDEF, U+xFFFE/U+xFFFF) | `filename_noncharacter` |
| No surrogates (U+D800-U+DFFF, e.g. via JSON `\ud800` escape) | `filename_surrogate` |
| No duplicate filenames (exact byte match) | `filename_dupe` |
| No duplicate filenames across types (file vs symlink) | `filename_dupe_cross` |

### `iffy/` -- security-focused decoders should reject; permissive decoders may accept

| Rule | Test case |
|---|---|
| Case collisions (`Foo` vs `foo`) | `filename_case_collision` |
| Non-canonically normalized name | `filename_nfd` |
| Non-canonical combining character order | `filename_combining_order` |
| Names differing only by Default-Ignorable characters (ZWJ, ZWNJ, soft hyphen, etc.) | `filename_default_ignorable` |

---

## Smuggling

ZAR does not attempt to prevent an archive from simultaneously being a valid instance of another format (a "turduckeon"). Prevention is not achievable: zstd compressed blocks (both stored and compressed) can carry arbitrary byte patterns, so any byte sequence can appear inside a conforming ZAR archive. Rejecting skippable frames would not close this; it would merely exclude one specific vector while leaving all others open. The zstd stream definition above therefore permits them. Zero-length frames (a valid zstd frame that decompresses to empty bytes) are likewise accepted without restriction. They are valid per RFC 8878 and introduce no confusion risk beyond what stored blocks already allow. The `manifest_sha256` and `contents_sha256` cover the full respective sections including any skippable or zero-length frames.

---

## Malicious case

`malicious/nfc_nfd_collision.zar` contains two files that are byte-distinct but canonically equivalent under Unicode normalization (`café.txt` precomposed U+00E9 vs `café.txt` decomposed). An implementation that checks raw bytes would accept both as distinct. Normalization is useful as a filesystem-independent pre-check: the pair collides on HFS+/APFS and on other NF[CD]-normalizing filesystems.
