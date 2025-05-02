import re
from deflate import Bitstream, DeflateReader

CMD_RE = re.compile(r'bit|byte|sync|[0-9a-fA-F]+|#.*|\s')

BIT = "bit"
BYTE = "byte"
SYNC = "sync"

def compile(s):
    buf = []
    active = 0
    m = 1
    mode = BYTE

    # Hacky way to make sure we understand the whole string
    if remainder := CMD_RE.sub("", s):
        raise ValueError(f"Unparseable data left: {remainder=}")

    for i in CMD_RE.findall(s):
        if i == BIT:
            mode = BIT
        elif i == BYTE:
            assert m == 1, "Switching to byte mode without sync"
            mode = BYTE
        elif i == SYNC:
            if m != 1:
                buf.append(active)
            active = 0
            m = 1
        elif i.startswith("#"):
            continue
        elif i.isspace():
            continue
        else:
            if mode == BIT:
                for c in i:
                    if c == "1":
                        active |= m
                    else:
                        assert c == "0"
                    m <<= 1
                    if m == 256:
                        buf.append(active)
                        active = 0
                        m = 1
            else:
                assert m == 1, "Byte input while not sync"
                n = int(i, 16)
                assert 0 <= n <= 255
                buf.append(n)
    if m != 1:
        buf.append(active)
    return buf

if __name__ == "__main__": # pragma: no cover
    print(compile("bit 00 10 00 00 1 sync byte 2"))
