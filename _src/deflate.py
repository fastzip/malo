from __future__ import annotations

MAXBITS = 15
MAXLCODES = 286
MAXDCODES = 30
MAXCODES = MAXLCODES + MAXDCODES
FIXLCODES = 288

CODE_ORDER = (16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15)
# Size base for length codes 257..285
LENS = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258
]
# Extra bits for length codes 257..285
LEXT = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
]
# Offset base for distance codes 0..29
DISTS = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577
]
# Extra bits for distance codes 0..29
DEXT = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11,
    12, 12, 13, 13
]

class Bitstream:
    def __init__(self, b):
        self.b = b
        self.i = 0
        self.j = 0

    def pos(self):
        """
        A fixed-length string representing the bitstream position for debugging.
        """
        return "%04x %s" % (self.i, (("+%d" % self.j) if self.j else "  "))

    def eof(self):
        return self.i == len(self.b)

    def next(self):
        """
        Raises IndexError if past the end.
        """
        r = (self.b[self.i] >> self.j) & 1
        self.j += 1
        if self.j == 8:
            print("next byte", self.i, hex(self.b[self.i]))
            self.i += 1
            self.j = 0
        print("next ->", r)
        return r

    def read(self, n_bits) -> tuple[int, ...]:
        lst = []
        for _ in range(n_bits):
            lst.append(self.next())
        return tuple(lst)

    def read_int(self, n_bits) -> int:
        n = 0
        m = 1
        for _ in range(n_bits):
            if self.next(): n += m
            m <<= 1
        return n

    def read_short(self) -> int:
        assert self.j == 0
        r = int.from_bytes(self.b[self.i:self.i+2], "little")
        self.i += 2
        return r

    def read_byte(self) -> int:
        assert self.j == 0
        r = self.b[self.i]
        self.i += 1
        return r

    def ignore_rest_of_byte(self):
        """
        Ensure that we're at the beginning of a byte.

        Does not check eof afterwards.
        """
        while self.j != 0:
            # print("discard")
            n = self.next()
            assert n == 0  # are people trying to smuggle data in the padding bits?

class DeflateReader:
    def __init__(self, filename, data=None):
        if data is None:
            with open(filename, "rb") as fo:
                data = fo.read()

        self.bs = bs = Bitstream(data)
        self.output = []
        self.dump_file()

    def dump_file(self):
        bs = self.bs

        while True:
            print(bs.pos(), end=" ")

            bfinal = bs.next()
            btype = bs.read(2)[::-1]


            if btype == (0, 0):
                # non-compressed blocks
                print("block btype=00")
                bs.ignore_rest_of_byte()

                print(bs.pos(), end=" ")
                len = bs.read_short()
                nlen = bs.read_short()
                print("  len", len)
                assert len ^ 0xffff == nlen, f"{len} != {nlen}"
                print(bs.pos(), end=" ")
                new = [bs.read_byte() for _ in range(len)]
                print("  data", new)
                self.output.extend(new)

            elif btype == (0, 1):
                # compressed, fixed huffman
                print("block btype=01")
                self.setup_fixed_huffman()
                self.read_compressed()
            elif btype == (1, 0):
                # compressed, dynamic huffman
                print("block btype=10")
                self.setup_dynamic_huffman()
                self.read_compressed()
            else:
                # error on (1, 1)
                print("block btype=11")
                raise DeflateError("btype 11 reserved")

            if bfinal:
                print("final set, done")
                break

        # assert bs.eof()
        print(self.output)

    def setup_fixed_huffman(self):
        self.symbols = self.fixed_symbols()
        self.distances = self.fixed_distances()

    def fixed_symbols(self):
        lengths = [0] * 288
        for i in range(144):
            lengths[i] = 8
        for i in range(144, 256):
            lengths[i] = 9
        for i in range(256, 280):
            lengths[i] = 7
        for i in range(280, 288):
            lengths[i] = 8
        return Huff(lengths, 288)

    def fixed_distances(self):
        lengths = [5] * 30
        return Huff(lengths, 30)

    def setup_dynamic_huffman(self):
        # Preferring the terminology from puff.c here, as well as initializing arrays to zero
        bs = self.bs
        nlen = bs.read_int(5) + 257
        ndist = bs.read_int(5) + 1
        ncode = bs.read_int(4) + 4
        print(f"  {nlen=} {ndist=} {ncode=}")

        assert nlen <= MAXLCODES
        assert ndist <= MAXDCODES

        lengths = [0] * MAXCODES

        for i in range(ncode):
            lengths[CODE_ORDER[i]] = bs.read_int(3)
        # Don't need zero from ncode to MAXCODES
        print("lengths", lengths)

        tab = Huff(lengths, 19)
        assert tab.left == 0

        #print(f"  {tab=}")
        index = 0

        while index < (nlen + ndist):
            symbol = tab.decode(bs)
            print(" dyn sym", symbol)
            if symbol < 16:
                lengths[index] = symbol
                print("  lit", symbol)
                index += 1
            else:
                rep = 0
                if symbol == 16:
                    assert index != 0
                    rep = lengths[index - 1]
                    symbol = 3 + bs.read_int(2)
                elif symbol == 17:
                    symbol = 3 + bs.read_int(3)
                else:
                    symbol = 11 + bs.read_int(7)

                assert (index + symbol) <= (nlen + ndist)
                for _ in range(symbol):
                    lengths[index] = rep
                    index += 1
            print("done dec", index)

        assert lengths[256] != 0
        self.symbols = Huff(lengths[:nlen], nlen)
        self.distances = Huff(lengths[nlen:], ndist)

    def read_compressed(self):
        while True:
            symbol = self.symbols.decode(self.bs)
            print("     sym =", symbol)
            if symbol < 256:
                # literal
                self.output.append(symbol)
                print()
            elif symbol == 256:
                break
            else:
                # length-distance
                symbol -= 257
                el = LENS[symbol] + self.bs.read_int(LEXT[symbol])
                symbol = self.distances.decode(self.bs)
                dist = DISTS[symbol] + self.bs.read_int(DEXT[symbol])
                print("    el =", el, " dist =", dist)
                assert dist < len(self.output)
                for _ in range(el):
                    self.output.append(self.output[-dist])
                print()

class Huff:
    def __init__(self, lengths, n):
        counts = [0] * (MAXBITS + 1)
        for sym in range(n):
            counts[lengths[sym]] += 1

        assert counts[0] != n

        left = 1
        for i in range(1, MAXBITS+1):
            left <<= 1
            left -= counts[i]
            assert left >= 0

        offsets = [0] * (MAXBITS + 1)
        for i in range(1, MAXBITS):
            offsets[i+1] = offsets[i] + counts[i]

        tab = [0] * n
        for sym in range(n):
            if lengths[sym]:
                p = offsets[lengths[sym]]
                tab[p] = sym
                offsets[lengths[sym]] += 1

        self.symbol = tab
        self.count = counts
        self.left = left
        print("  tab", tab)
        print("  count", counts)
        print("  left", left)

    def decode(self, bs):
        code = 0
        first = 0
        index = 0
        for length in range(1, MAXBITS+1):
            code |= bs.next()
            count = self.count[length]
            if code - count < first:
                return self.symbol[index + (code - first)]
            index += count
            first += count
            first <<= 1
            code <<= 1

        raise ValueError("maxbits exceeded")


if __name__ == "__main__":
    import sys
    DeflateReader(sys.argv[1])
