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
gen(
    "accept/data_descriptor_zip64.zip",
    """
lfh flags=8 method=8 extra_length=4
short 1 0
mark x
deflate b"hello"
mark y
# data descriptor now, crc csize usize
long 0x08074b50 0x3610a686 
quad =y-x =5
mark start_of_cd
cd csize=y-x usize=5 crc32=0x3610a686 method=8
eocd num_entries_this_disk=1 num_entries_total=1 offset_start=start_of_cd size=.-start_of_cd
""")
gen(
    "reject/data_descriptor_zip64_csize.zip",
    """
lfh flags=8 method=8 extra_length=4
short 1 0
mark x
deflate b"hello"
mark y
# data descriptor now, crc csize usize
long 0x08074b50 0x3610a686 
quad =y-x+1 =5
mark start_of_cd
cd csize=y-x usize=5 crc32=0x3610a686 method=8
eocd num_entries_this_disk=1 num_entries_total=1 offset_start=start_of_cd size=.-start_of_cd
""")
gen(
    "reject/data_descriptor_zip64_usize.zip",
    """
lfh flags=8 method=8 extra_length=4
short 1 0
mark x
deflate b"hello"
mark y
# data descriptor now, crc csize usize
long 0x08074b50 0x3610a686 
quad =y-x =6
mark start_of_cd
cd csize=y-x usize=5 crc32=0x3610a686 method=8
eocd num_entries_this_disk=1 num_entries_total=1 offset_start=start_of_cd size=.-start_of_cd
""")
gen(
    "accept/zip64_eocd.zip",
    """
lfh flags=0 method=8 csize=y-x usize=5 crc32=0x3610a686
mark x
deflate b"hello"
mark y
mark start_of_cd
cd csize=y-x usize=5 crc32=0x3610a686 method=8
mark end_of_cd
z64eocd num_entries_this_disk=1 num_entries_total=1 offset_start=start_of_cd size_of_cd=end_of_cd-start_of_cd
z64loc relative_offset=end_of_cd
eocd num_entries_this_disk=1 num_entries_total=1 offset_start=0xffffffff size=0xffffffff
""")
gen(
    "iffy/zip64_eocd_extensible_data.zip",
    """
lfh flags=0 method=8 csize=y-x usize=5 crc32=0x3610a686
mark x
deflate b"hello"
mark y
mark start_of_cd
cd csize=y-x usize=5 crc32=0x3610a686 method=8
mark end_of_cd
z64eocd num_entries_this_disk=1 num_entries_total=1 offset_start=start_of_cd size_of_cd=end_of_cd-start_of_cd extensible_data=b"\\x00\\x00\\x10\\x00zzzzzzzzzzzzzzzz"
z64loc relative_offset=end_of_cd
eocd num_entries_this_disk=0xffff num_entries_total=0xffff offset_start=0xffffffff size=0xffffffff
""")
gen(
    "malicious/zip64_eocd_confusion.zip",
    """
# First zip contents
lfh flags=0 method=8 csize=y-x usize=5 crc32=0x3610a686
mark x
deflate b"hello"
mark y
mark start_of_cd
cd csize=y-x usize=5 crc32=0x3610a686 method=8
mark end_of_cd
z64eocd num_entries_this_disk=1 num_entries_total=1 offset_start=start_of_cd size_of_cd=end_of_cd-start_of_cd size=b-end_of_cd-12

# These four bytes need to look like a zip64 eocd, but also need to look like a valid extra.
mark tmp

z64loc relative_offset=end_of_cd
eocd num_entries_this_disk=0xffff num_entries_total=0xffff offset_start=0xffffffff size=0xffffffff comment_length=end-tmp2
mark tmp2

assert 6060 =b-tmp-4
pad =24672-165-22

# Second zip contents
mark start2
lfh flags=0 method=8 csize=y2-x2 usize=5 crc32=0x551e5fb4 filename=b"secon"
mark x2
deflate b"BOOM!"
mark y2
mark start_of_cd2
cd csize=y2-x2 usize=5 crc32=0x551e5fb4 method=8 header_offset=0 filename=b"secon"

mark a
z64eocd num_entries_this_disk=1 num_entries_total=1 offset_start=start_of_cd size_of_cd=end_of_cd-start_of_cd
mark b
z64loc relative_offset=end_of_cd
eocd num_entries_this_disk=0xffff num_entries_total=0xffff offset_start=0xffffffff size=0xffffffff
mark end
""")
