---
hackmd: MeNFtl5qRWi2HhTKdhis1A
---
# Archive-safe Unicode

The primary goal of a good archive format is not just to store bytes faithfully, and unpack boringly: follow the _intent_ of the packer.  A packer who wrote `Résumé.pdf` and `résumé.pdf` clearly intended there to be two files extracted -- depending on the target filesystem, this might not be achievable.

Truly preventing all name collisions at archive-creation time is impossible.  The only authoritative arbiter of whether two names collide is the target filesystem at extraction time.  What we _can_ do is:

1. **Require a valid, unambiguous encoding** so implementors don't have to guess what the packer meant.
2. **Apply the union of common filesystem normalization rules** as a conservative pre-check that catches likely collisions before anything is written to disk.
3. **Surface these errors as early as possible** -- ideally at pack time, certainly before extraction begins; they otherwise become silent data-loss bugs for some fraction of users.
4. **Use safe unpacking syscalls** -- see [design.md §5](design.md) for platform-specific guidance on `O_CREAT`, `openat2`, and Windows equivalents

Case-sensitivity is the biggest source of these surprises.  Many popular filesystems (NTFS on Windows, APFS on Mac, ext4-casefold on Linux) can be case-insensitive, meaning `Foo.txt` and `foo.txt` are the same file.  An archive that contains both will extract correctly on a case-sensitive Linux ext4 filesystem and silently do something different on everything else unless care is taken.

**If your (the user's) use case genuinely requires case-sensitive filenames**, you may make that choice -- but you should do so explicitly and document it clearly, because you are requiring case-sensitivity of every user who extracts the archive on every filesystem they will ever use.  That is a much stronger claim than it sounds, and for most people is accidental.

For the default, common case, this spec's recommendation is: treat case collisions (and their Unicode generalisations) as errors by default, with an explicit escape hatch for advanced users who understand the tradeoff.  Warnings-as-errors is a reasonable default; a `--allow-case-collisions` flag is a reasonable escape hatch.

# 1. Encoding Itself

## 1.1 Valid Unicode

While most filesystems either store bytes (good luck, user) or include a bytes fallback to at least be able to roundtrip invalid names, the variety of these rules necessitates being strict about what the intent is.  If _you_ don't know how to fix the encoding when creating an archive, you users certainly won't.

## 1.2 Stored as Valid UTF-8

In addition to the non-controversial choice of UTF-8 for storage, this spec is also explicit about two non-obvious restrictions as part of "valid":

- No overlong encodings (e.g. `c0 80`, `e0 80 80`, `f0 80 80 80`)
- No surrogates alone (`ed a0 80`) or in pairs (`ed a0 80 ed b0 80`), or in reversed pairs (`ed b0 80 ed a0 80`)
- No invalid bytes (e.g. `ff` is neither a start nor continue byte)

These rules are implied by RFC 3628 (UTF-8 itself), and already behavior of Python's `bytes.decode("utf-8")`.  You MUST validate the UTF-8 on load, not just trust that it is.

For avoidance of doubt: You MUST NOT perform operations such as truncation or using U+FFFE (replacement character) in place of invalid bytes.  Expect that every step along the distribution path WILL validate UTF-8 well-formedness.

# 2 Paths

## 2.1 Path Separator

The only allowed path separator is `/`, full stop.  All paths MUST be relative and minimal, so `'/foo'` (absolute) and `'./foo'` are both not allowed.  More details are in the next couple sections.

Simply take the components, join them with `/`.

As a note, Windows paths like `'D:\'` and `'\\?\'` and `'\\server\share'` will already fail these checks and do not need to be validated separately, but may if you wish to produce a better error.

## 1.2 Reserved Characters

After decoding UTF-8, you MUST immediately reject paths with these characters anywhere within the string:

- U+0000 (null)
- U+003A (colon, `':'`)
- U+005C (backslash, `'\'`)
- U+FEFF (BOM, both at start and anywhere else)
- Surrogates:
  - U+D800-U+DFFF (permanently reserved)
- Reserved Non-characters:
  - U+FDD0-U+FDEF (permanently reserved)
  - U+FFFE and U+FFFF (permanently reserved)
  - The last two code points of each supplementary plane (U+1FFFE, U+1FFFF, U+2FFFE, U+2FFFF, ..., U+10FFFE, U+10FFFF; permanently reserved)

Non-BMP code points (U+10000-U+10FFFF, encoded as 4-byte UTF-8 sequences) are explicitly permitted.  This includes emoji, historic scripts, supplementary CJK, and other assigned characters in planes 1-14, as well as the supplementary private-use areas in planes 15-16.  The non-characters and last-two-code-points listed above are excluded, but everything else in this range is fine.

Private-use code points more broadly (BMP private-use area U+E000-U+F8FF, plus the supplementary private-use areas) are also explicitly permitted; their interpretation is application-defined and no filesystem strips them.

> Tim: null is an obvious one -- but the strictness here is to reject, not truncate or anything else.  Colon can refer to drive letters on Windows, alternate streams on Windows, and was a historical path separator on MacOS.  Surrogates aren't allowed, but a surprising number of filesystems do... something... with them.  These are about increasing predictability across platforms, regardless of where the archive is created.

## 1.3 Reserved Components

These rules are about prohibiting some things that are hard to normalize consistently, without trying to emulate any particular platform

The following components are reserved and MUST NOT be used in interchange.

- `'.'` and `".."` (current and parent dir, as in `./foo` or `foo/../bar`)
- `''` (empty, as in `foo//bar`)
- Any components that endswith `'.'` or `' '` (these get trimmed by some Windows APIs, and are of questionable usefulness elsewhere)

## 1.4 Explicitly non-reserved components

Unpackers are expected to prohibit platform-specific weirdness using appropriate APIs.  These filenames are allowed in archives, and errors-by-default can apply here to prevent use by accident.

- `'CON'` and `'CON..txt'`
- `'PROGRA~1'` (if that is the short name for something -- the common case can be prevalidated with regex, but short names *can* be arbitrary)


# 2. Name Normalization

## 2.1 Unicode Normalization rules (C+F)

Many systems apply NFD (or a subset) normalization when comparing names, either on read or write.  The exact stored utf-8 does not determine whether two names collide; the target filesystem does.  No particular normalization form is required, and original case should be stored.  Even when you do not have an actual filesystem to query, normalization checks are still useful as a conservative pre-flight collision test.

**Unpackers**: Check for names that are equivalent under NFD(casefold(NFD)) and treat collisions as iffy (see [spec.md](spec.md)).  The casefold step SHOULD use full Unicode case folding (not simple case folding): `str.casefold()` in Python, or `golang.org/x/text/cases` with `Fold` option in Go.  Simple case folding (e.g. Go's `strings.EqualFold`) will defer more detection to unpack time, since it does not map ligatures or ß to their multi-character equivalents.

## 2.2 Compatibility normalization (K)
e.g. NFKC (Compatibility Normalization) is intentionally not applied: no common filesystem uses NFKC when comparing names, so NFKC-equivalent but NFC-distinct names (e.g. `²file.txt` and `2file.txt`) are legitimately different files and must be accepted.  The same applies to Unicode lookalikes and confusables generally -- they are a social engineering concern, not a filesystem one.  More subtly, equal-CCC combining marks can have multiple equivalent representations (for example, marks that differ only in ordering when they canonically commute), so normalization is still useful as a collision check even when the strings do not look obviously related.

## 2.3 Default-Ignorable

Linux strips these for ext4 when comparing _but only in case-insensitive mode_.  Packers SHOULD check for collisions and warn, but this affects fewer systems and is probably less common characters, so are not required to error.
