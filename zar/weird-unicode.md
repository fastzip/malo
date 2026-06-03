
# Appendix A: Weird Behaviors

## Greek

This section is about `iffy/`-style collision behavior rather than a hard reject rule: a strict unpacker should normalize and treat the affected names as colliding, while a permissive one may choose to accept them.

Two characters:

1. One whose NFKC_Casefold expansion a) is multi-character b) that expansion ends in a base letter (ccc=0)
2. A combining mark that can legally compose with that base letter

Alpha with ypogegrammeni and acute
```
input = U+1FB3 U+0301 (a little unusual)
NFC = U+1FB4
NFD = U+03B1 U+0301 U+0345

CaseFolding.txt, raw input
U+03B1 U+03B9 U+0301 (in NFD, by chance here)

CaseFolding.txt, NFC
U+30AC U+03B9 (in NFC)

CaseFolding.txt, NFD input
U+03B1 U+0301 U+0345 (unmodified)


NFKC(str.casefold(NFKC(x)))
U+03AC U+03B9 = "άι" (already NFC)
  U+30AB U+3099 U+03B9 (in NFD)

icu.Normalizer2.getNFKCCasefoldInstance().normalize
U+03B1 U+03AF = "αί" (already NFC)
  U+03B1 U+03B9 U+0301 (in NFD)

str.casefold
U+03B1 U+03B9 U+0301 = "αί"
```

Why? CCC determines the canonical combining mark ordering (it's by vertical position in the line).  Case-folding does not change CCC, EXCEPT for U+0345 (one of the )

Simplified detection: U+1F80 to U+1FFC, U+037A present

D2: NFD(toCaseFold(NFD(str)))
D3: NFKD(toCaseFold(NFKD(toCaseFold(NFD(str)))))

## Turkic

These should be excluded

## Joiners

Linux removes Default_Ignorable_Code_Point (including ZWJ and ZWNJ) which results in some weirdness

```
U+1F468 U+200D U+1F4BB (person-on-computer, ZWJ forces together except on my terminal)

Only on Linux casefold (NFDICF):
U+1F468 U+1F4BB (person, then computer emoji)
```

Farsi ZWNJ

U+200C

## CCC ties

These are most legal in Greek as well.

```
U+1F04 has two accents above
has two possible orderings
```
U+10400 / U+10428 (Deseret) are not case-folded. NTFS stores them as surrogate pairs in UTF-16 and treats them as opaque.
Unpaired surrogates are permitted by NTFS.
