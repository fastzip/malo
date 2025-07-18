import sys
from pathlib import Path

sys.path.append("../_src")

import zipwoot

def gen(fn, script):
    data = zipwoot.compile(script)
    Path(fn).write_bytes(data)

gen(
    "accept/normal_deflate.zip",
    """
lfh flags=0 method=8 csize=y-x usize=5 crc32=0x3610a686
mark x
deflate b"hello"
mark y
mark start_of_cd
cd csize=y-x usize=5 crc32=0x3610a686 method=8
eocd num_entries_this_disk=1 num_entries_total=1 offset_start=start_of_cd size=.-start_of_cd
""")

gen(
    "accept/normal_deflate_zip64_extra.zip",
    """
lfh flags=0 method=8 csize=0xffffffff usize=5 crc32=0x3610a686 extra_length=x-w
mark w
short 1 8
quad =y-x
mark x
deflate b"hello"
mark y
mark start_of_cd
cd csize=0xffffffff usize=5 crc32=0x3610a686 method=8 extra_length=x-w
short 1 8
mark h
quad =y-x
eocd num_entries_this_disk=1 num_entries_total=1 offset_start=start_of_cd size=.-start_of_cd
""")
gen(
    "reject/zip64_extra_csize.zip",
    """
lfh flags=0 method=8 csize=0xffffffff usize=5 crc32=0x3610a686 extra_length=x-w
mark w
short 1 8
quad =y-x+1
mark x
deflate b"hello"
mark y
mark start_of_cd
cd csize=0xffffffff usize=5 crc32=0x3610a686 method=8 extra_length=x-w
short 1 8
mark h
quad =y-x+1
eocd num_entries_this_disk=1 num_entries_total=1 offset_start=start_of_cd size=.-start_of_cd
""")
gen(
    "reject/zip64_extra_usize.zip",
    """
lfh flags=0 method=8 csize=y-x usize=0xffffffff crc32=0x3610a686 extra_length=x-w
mark w
short 1 8
quad =5+1
mark x
deflate b"hello"
mark y
mark start_of_cd
cd csize=y-x usize=0xffffffff crc32=0x3610a686 method=8 extra_length=x-w
short 1 8
mark h
quad =5+1
eocd num_entries_this_disk=1 num_entries_total=1 offset_start=start_of_cd size=.-start_of_cd
""")
gen(
    "iffy/zip64_extra_too_short.zip",
    """
lfh flags=0 method=8 csize=0xffffffff usize=0xffffffff crc32=0x3610a686 extra_length=x-w
mark w
short 1 8
quad 5
mark x
deflate b"hello"
mark y
mark start_of_cd
cd csize=0xffffffff usize=0xffffffff crc32=0x3610a686 method=8 extra_length=x-w
short 1 8
mark h
quad 5
eocd num_entries_this_disk=1 num_entries_total=1 offset_start=start_of_cd size=.-start_of_cd
""")
gen(
    "iffy/zip64_extra_too_long.zip",
    """
lfh flags=0 method=8 csize=y-x usize=0xffffffff crc32=0x3610a686 extra_length=x-w
mark w
short 1 10
quad 5 0
mark x
deflate b"hello"
mark y
mark start_of_cd
cd csize=y-x usize=0xffffffff crc32=0x3610a686 method=8 extra_length=x-w
short 1 10
mark h
quad 5 0
eocd num_entries_this_disk=1 num_entries_total=1 offset_start=start_of_cd size=.-start_of_cd
""")

gen(
    "reject/cd_missing_entry.zip",
    """
lfh flags=0 method=8 csize=y-x usize=5 crc32=0x3610a686
mark x
deflate b"hello"
mark y
lfh flags=0 method=8 csize=y-x usize=5 crc32=0x3610a686 filename=b"two"
deflate b"hello"
mark z
mark start_of_cd
cd csize=y-x usize=5 crc32=0x3610a686 method=8
eocd num_entries_this_disk=1 num_entries_total=1 offset_start=start_of_cd size=.-start_of_cd
""")

gen(
    "reject/cd_extra_entry.zip",
    """
lfh flags=0 method=8 csize=y-x usize=5 crc32=0x3610a686
mark x
deflate b"hello"
mark y
mark start_of_cd
cd csize=y-x usize=5 crc32=0x3610a686 method=8
cd csize=y-x usize=5 crc32=0x3610a686 method=8
eocd num_entries_this_disk=2 num_entries_total=2 offset_start=start_of_cd size=.-start_of_cd
""")

gen(
    "accept/data_descriptor.zip",
    """
lfh flags=8 method=8
mark x
deflate b"hello"
mark y
# data descriptor now, crc csize usize
long 0x08074b50 0x3610a686 =y-x =5
mark start_of_cd
cd csize=y-x usize=5 crc32=0x3610a686 method=8
eocd num_entries_this_disk=1 num_entries_total=1 offset_start=start_of_cd size=.-start_of_cd
""")
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
