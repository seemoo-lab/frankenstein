import lief
import sys
import json
import shutil

"""
Patches the symbol table of a compiled emulator to export symbols
This is required to load the firmware back in to a reverse engineering software
TODO symbol types are currently not stored in project.json
"""

if len(sys.argv) != 3:
    print("usage: %s project.json elf" % sys.argv[0])
    sys.exit(-1)

project_fd = open(sys.argv[1], "r")
project = json.load(project_fd)

elf = lief.parse(sys.argv[2])

for name in project["symbols"]:
    symbol = elf.get_symbol(name)
    symbol.type = lief.ELF.SYMBOL_TYPES.FUNC
    symbol.exported = True

for sg in project["segment_groups"]:
    for name in project["segment_groups"][sg]["symbols"]:
        symbol = elf.get_symbol(name)
        symbol.type = lief.ELF.SYMBOL_TYPES.FUNC
        symbol.exported = True

elf.write(sys.argv[2]+".patched")
del elf
shutil.move(sys.argv[2]+".patched", sys.argv[2])
