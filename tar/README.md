# tar test corpus

This corpus validates **PAX (POSIX.1-2001) tar** only. GNU tar and bsdtar both
produce PAX by default, so there is no practical reason to accept older
extension formats.

GNU-specific extensions (`L`/`K` long-name headers, old-GNU sparse `S` blocks,
GNU magic `"ustar  \0"`) are placed in `reject/` or `iffy/` because PAX
provides clean replacements for all of them:

| GNU extension | PAX replacement |
|---|---|
| `L` typeflag (long filename) | `path` attribute in `x` header |
| `K` typeflag (long link name) | `linkpath` attribute in `x` header |
| old-GNU sparse (`S` typeflag) | `GNU.sparse.*` or `SCHILY.sparse.*` attributes |

## Categories

- **accept/** — well-formed PAX archives a correct parser must accept
- **iffy/** — technically parseable but ambiguous or unusual; security-minded
  parsers may reject
- **malicious/** — adversarial archives; should be rejected or handled with
  extreme caution
- **reject/** — structurally invalid or uses unsupported extensions; a correct
  parser must reject
