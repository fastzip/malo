import sys
from pathlib import Path

sys.path.append("../_src")

import zipwoot

def gen(fn, script):
    data = zipwoot.compile(script)
    Path(fn).write_bytes(data)

gen(
    "reject/data_descriptor_bad_crc.zip",
    """
lfh flags=8 method=8
mark x
deflate b"hello"
mark y
# data descriptor now, crc csize usize
long 0x08074b50 1 =y-x 5
mark start_of_cd
cd csize=y-x usize=5 crc32=0x3610a686 method=8
eocd num_entries_this_disk=1 num_entries_total=1 offset_start=start_of_cd size=.-start_of_cd
""")

gen(
    "reject/data_descriptor_bad_crc_0.zip",
    """
lfh flags=8 method=8
mark x
deflate b"hello"
mark y
# data descriptor now, crc csize usize
long 0x08074b50 0 =y-x 5
mark start_of_cd
cd csize=y-x usize=5 crc32=0x3610a686 method=8
eocd num_entries_this_disk=1 num_entries_total=1 offset_start=start_of_cd size=.-start_of_cd
""")

gen(
    "reject/data_descriptor_bad_csize.zip",
    """
lfh flags=8 method=8
mark x
deflate b"hello"
mark y
# data descriptor now, crc csize usize
long 0x08074b50 0x3610a686 =y-x+1 5
mark start_of_cd
cd csize=y-x usize=5 crc32=0x3610a686 method=8
eocd num_entries_this_disk=1 num_entries_total=1 offset_start=start_of_cd size=.-start_of_cd
""")

gen(
    "reject/data_descriptor_bad_usize.zip",
    """
lfh flags=8 method=8
mark x
deflate b"hello"
mark y
# data descriptor now, crc csize usize
long 0x08074b50 0x3610a686 =y-x =5+1
mark start_of_cd
cd csize=y-x usize=5 crc32=0x3610a686 method=8
eocd num_entries_this_disk=1 num_entries_total=1 offset_start=start_of_cd size=.-start_of_cd
""")

gen(
    "reject/data_descriptor_bad_usize_no_sig.zip",
    """
lfh flags=8 method=8
mark x
deflate b"hello"
mark y
# data descriptor now, crc csize usize
long 0x3610a686 =y-x =5+1
mark start_of_cd
cd csize=y-x usize=5 crc32=0x3610a686 method=8
eocd num_entries_this_disk=1 num_entries_total=1 offset_start=start_of_cd size=.-start_of_cd
""")
