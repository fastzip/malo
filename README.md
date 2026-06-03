Malo is a resource for those writing security-minded file formats.

Each of the archive/compression formats has subdirectories named:

* accept (valid by the spec)
* iffy (weird, but technically valid and unambiguous)
* malicious (weird, plausibly valid but in a bad/ambiguous way)
* reject (invalid by the spec)

A permissive decoder may accept all of them. A security-minded one accepts
only the `accept` group and rejects everything else.

The contributors believe there to be the beginnings of parser differentials
invited by accepting any of `iffy` or `malicious` (for example, ignoring
checksums).

SPDX-License-Identifier: CC0-1.0 OR BSD-2-Clause
