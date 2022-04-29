# export reversed function names and globals from IDA to Frankenstein JSON format

from idautils import *
from idaapi import *
from idc import *
import os

# save output here
outfolder = "/tmp/frankenstein/"

if not os.path.exists(outfolder):
    os.makedirs(outfolder)

f = open(outfolder + "project.json", "w")

# search database for segments
def search_segments():
    segments = ""
    for segea in Segments():

        # segment info
        start = segea
        l = get_segm_end(segea) - segea
        name = 'Segment_' + hex(start)  # name as used within Frankenstein
        segments += '                ' + name + '": {"active": true, "addr": ' + str(start) + ', "size": ' + str(l) + '},\n'

        # we also need to read all bytes from the segment
        b = open(outfolder + name + '.bin', "wb")
        b.write(get_bytes(start, l))
        b.close()

    segments = segments[:-2]  # remove last comma from list
    return segments

# search database for functions and globals.
# we define semantics in C later on when writing code.
# here, we only care about names.
def search_names():
    names = ""
    for name in Names():
        names += f"    \"{name[1]}\": {name[0]},\n"
    names = names[:-2]  # remove last comma
    return names

print("[+] Starting export...")

print("""{
    "config": {
        "EMULATION_CFLAGS": "-c -static -fpic -pie -nostdlib -g -Ttext $(EMULATION_CODE_BASE) -I include  -I gen -I ../../include  -I /usr/include -D FRANKENSTEIN_EMULATION",
        "EMULATION_CODE_BASE": 200208384,
        "PATCH_CFLAGS": "-O2 -static -nostdlib -Tgen/patch.ld -mcpu=cortex-m4 -I include-I gen -I ../../include",
        "PATCH_CODE_BASE": 200208384,
        "TOOLCHAIN": "arm-none-eabi-",
        "thumb_mode": true
    },
    "segment_groups": {
        "default": {
            "active": true,
            "segments": {
%s
            },
            "symbols": {}
        }
    },
    "symbols": {
%s
    }
}""" % (search_segments(), search_names()), file=f)

print("[+] Exported segments and names to " + outfolder)
print("[!] after export, open the project in the web view and update one symbol to order them correctly.")
