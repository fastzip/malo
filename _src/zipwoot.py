import ast
import struct
import sys
import re
import zlib
from io import BytesIO

from woot import compile as bit_compile
from ziptypes import LocalFileHeader, CentralDirectoryHeader, EOCD, Zip64EOCDLocator, Zip64EOCD

# TODO rewind?
# TODO insert mode?
# TODO num x count

LINE_RE = re.compile(
    r'((?P<cmd>\w+)[ \t]+(?P<rest>.*))?(?P<comment>[ \t]*#.*)?\n'
)

def name(tok):
    return [k for k, v in tok.groupdict().items() if v is not None][0]

def restofline(it):
    line = ""
    while not line.endswith("\n"):
        if line:
            line += " "
        line += next(it).group(0)
    return line

FORMATS = {
    "short": "<H",
    "long": "<L",
    "quad": "<Q",
}

STRUCTURES = {
    "eocd": EOCD,
    "z64loc": Zip64EOCDLocator,
    "z64eocd": Zip64EOCD,
    "cd": CentralDirectoryHeader,
    "lfh": LocalFileHeader,
}

def compile(s):
    buf = BytesIO()
    env = {}

    def h(expr):
        if expr.startswith("="):
            expr = expr[1:].replace(".", "cur")
            env["cur"] = buf.tell()
            try:
                return eval(expr, env, env)
            except NameError as e:
                nonlocal forward_reference
                forward_reference = True
                return 0
        else:
            return int(expr, 16)

    def d(tmp):
        args = {}
        for arg in tmp.split():
            k, eq, v = arg.partition("=")
            if v.isdigit():
                args[k] = h(v)
            else:
                args[k] = h(eq + v)
        return args


    for _ in range(5):
        buf.seek(0, 0)
        buf.truncate()

        forward_reference = False
        for line in LINE_RE.finditer(s):
            n = line.group("cmd")
            c = line.group("comment")
            if not n and not c:
                continue

            print("> " + line.group(0).rstrip())

            if not n:
                continue

            start_pos = buf.tell()
            if n in ("bit", "byte"):
                buf.write(bytes(bit_compile(line.group("rest"))))
            elif n in ("short", "long", "quad"):
                f = FORMATS[n]
                for t in line.group("rest").split():
                    buf.write(struct.pack(f, h(t)))
            elif n == "deflate":
                arg = line.group("rest")
                val = ast.literal_eval(arg)
                buf.write(zlib.compress(val, -1, -15))
            elif n in STRUCTURES:
                args = d(line.group("rest"))
                e = STRUCTURES[n](**args)
                buf.write(e.pack())
            elif n == "mark":
                key = line.group("rest")
                env[key] = buf.tell()
                continue
            elif n == "assert":
                a, b = line.group("rest").split()
                av = h(a)
                bv = h(b)
                if av != bv:
                    raise AssertionError(f"{av!r} != {bv!r}")
                continue
            else:
                raise NotImplementedError(n)

            print("  | " + " ".join("%02x" % c for c in buf.getvalue()[start_pos:]), file=sys.stderr)

        if not forward_reference:
            return buf.getvalue()

    raise Exception("Could not complete forward references after some tries")

if __name__ == "__main__":
    compile("""\
mark x
# comment
byte 1 2 3
assert =.-x 3
long =.-x
mark n

lfh filename=b"z"
cd filename=b"z"
eocd num_entries_this_disk=5 comment=b"xyz"
z64eocd num_entries_this_disk=5
z64loc relative_offset=n
deflate b"abc"
""")
