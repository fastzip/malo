# TAR layout

This corpus targets PAX tar as the normal case. Older GNU extensions show up in `iffy/` and `reject/` because they are structurally distinct and easy sources of parser differential bugs.

## Top-level order

| Piece | Size | Count / order |
|---|---:|---|
| File header | 512 bytes | One per archive member |
| File data | `size` bytes, padded to 512 | Immediately after the header |
| PAX extended header (`x`) | 512-byte header + padded text payload | Optional, usually applies to the next member only |
| PAX global header (`g`) | 512-byte header + padded text payload | Optional, affects later members until replaced |
| End-of-archive | 1024 zero bytes | Usually exactly one trailer at the end |

## Core record shapes

| Record | Size | Notes |
|---|---:|---|
| `TarHeader` | 512 bytes | POSIX ustar header; all fixed fields are inside this one block |
| GNU long-name / long-link helper | 512-byte header + padded data | Implemented as a header with typeflag `L` or `K`, followed by one data block |
| Old GNU sparse header | 512 bytes | Classic sparse layout with up to 4 inline sparse entries in the first header |
| PAX record | Variable | ASCII line of the form `LEN SP key=value LF`; `LEN` includes its own digits and the space |

## `TarHeader` structure

The fixed tar header is always exactly one 512-byte block. The bytes are laid out as:

| Field group | Width |
|---|---:|
| Name | 100 |
| Mode / uid / gid | 8 / 8 / 8 |
| Size / mtime | 12 / 12 |
| Checksum | 8 |
| Typeflag | 1 |
| Linkname | 100 |
| Magic / version | 6 / 2 |
| Uname / gname | 32 / 32 |
| Dev major / minor | 8 / 8 |
| Prefix | 155 |
| Padding | 12 |

Notes that matter for parsers:

* Numeric fields are ASCII octal in normal output.
* `size` is the payload byte count for the member body, not including the 512-byte header.
* `pad_data()` rounds the payload up to the next 512-byte boundary.
* `end_of_archive()` is two zero blocks, so the archive trailer is 1024 bytes.

## Ordering rules to assume

* A normal member is `header -> data -> padding`.
* A PAX `x` header is `header -> text payload -> padding -> next member`.
* A PAX `g` header is the same shape, but its attributes remain in effect for later members.
* GNU `L` and `K` records are `header -> name/linkname payload -> padding -> next member`.
* Sparse members still occupy one 512-byte header, but their logical size can be much larger than the on-disk payload.

## Typical counts

* One header per archive member.
* One data payload per regular file member.
* Zero or one `x` header immediately before a file in normal PAX usage.
* Zero or more `g` headers in an archive, though multiple global headers are unusual.
* Exactly one end-of-archive trailer in well-formed archives, though some writers may append extra zeros.

