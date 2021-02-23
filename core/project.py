import json
import os
import shutil
from distutils.spawn import find_executable
import inspect

from core.loaders.elf import elfloader

makefile = """
.PHONY=all

SEGMENTS_RAW=$(wildcard segment_groups/*/*.bin)
SEGMENTS_OBJ=$(patsubst segment_groups/%.bin, gen/%.segment.o, $(SEGMENTS_RAW))

SRC_EMU=$(wildcard emulation/*.c)
OBJ_EMU=$(patsubst emulation/%.c, gen/%.exe, $(SRC_EMU))

SRC_PATCH=$(wildcard patch/*.c)
OBJ_PATCH=$(patsubst patch/%.c, gen/%.patch, $(SRC_PATCH))


#make linkable object from memory dump
gen/%.segment.o : segment_groups/%.bin
	@mkdir $(shell dirname $@) 2>/dev/null || true
	$(TOOLCHAIN)ld -r -b binary -o $@ $^

#create executable
gen/%.exe : emulation/%.c
	$(TOOLCHAIN)gcc $(EMULATION_CFLAGS) -o gen/src.o $^
	$(TOOLCHAIN)ld -T gen/segments.ld -o $@  --no-warn-mismatch

#patches
gen/%.patch : patch/%.c
	$(TOOLCHAIN)gcc $(PATCH_CFLAGS) -o $@ $^

all: clean $(SEGMENTS_OBJ) $(OBJ_EMU) $(OBJ_PATCH)

clean:
	@echo clean
	@rm gen/src.o 2>/dev/null || true
	@rm $(SEGMENTS_OBJ) 2>/dev/null || true
	@rm $(OBJ_EMU) 2>/dev/null || true
	@rm $(OBJ_PATCH) 2>/dev/null || true
"""

patch_ld = """
INCLUDE gen/symbols.ld;
ENTRY(_start);
SECTIONS {
    . = 0x%x;
    .text : { *(.text) }
    .data : { *(.data) }
    .bss : { *(.bss) }
}
"""

symbol_name_blacklist = [
    "_start",
    "exit"
]


class Project:
    def __init__(self, path, allow_create=True):
        self.path = path
        if not os.path.isdir(path):
            if not allow_create:
                print("Project %s does not exist")
                raise Exception()

            os.mkdir(path)
            os.mkdir(path + "/gen")
            os.mkdir(path + "/segment_groups")
            os.mkdir(path + "/segment_groups/default")
            os.mkdir(path + "/include")
            os.mkdir(path + "/emulation")
            os.mkdir(path + "/patch")


        if not os.path.isfile("%s/project.json" % self.path):
            if not allow_create:
                print("Project %s does not exist")
                raise Exception()

            self.cfg = {}
            self.cfg["segment_groups"] = {"default":{"active":True, "symbols":{}, "segments":{}}}
            self.cfg["symbols"] = {}
            self.cfg["config"] = {}
            self.cfg["config"]["TOOLCHAIN"] = "arm-none-eabi-"
            self.cfg["config"]["EMULATION_CFLAGS"] = "-c -static -fpic -pie -nostdlib -g -Ttext $(EMULATION_CODE_BASE) -I include  -I gen -I ../../include  -I /usr/include -D FRANKENSTEIN_EMULATION"
            self.cfg["config"]["PATCH_CFLAGS"] = "-O2 -static -nostdlib -Tgen/patch.ld -mcpu=cortex-m4 -I include-I gen -I ../../include"
            self.cfg["config"]["EMULATION_CODE_BASE"] = 0xbeef000
            self.cfg["config"]["PATCH_CODE_BASE"] = 0xbeef000
            self.cfg["config"]["thumb_mode"] = True
            self.save()

        else:
            with open("%s/project.json" % self.path, "r") as f:
                self.cfg = json.loads(f.read())

        self.error_msgs = ""

    def save(self):
        with open("%s/project.json" % self.path, "w") as f:
            data = json.dumps(self.cfg, indent=4, sort_keys=True)
            f.write(data)
        self.create_build_scripts()

        return True

    def error(self, msg):
        stack = inspect.stack()[2]
        fname = os.path.basename(stack[1])
        lineno = stack[2]
        func = stack[3]
        caller = "%s:%d %s(): " % (fname, lineno, func)
        self.error_msgs += caller + msg + "\n"
        print(caller + msg)


    """
    Import data from files
    """
    def load_symbol_csv(self, fname, groupName):
        for line in open(fname, "rb"):
            try:
                line = line.replace("\n", "")
                line = line.replace("\r", "")
                line = line.replace(" ", "")
                line = line.replace("\t", "")
                name, value = line.split(",")
                self.add_symbol(groupName, name, int(value, 16))
            except:
                print(line)
                import traceback; traceback.print_exc()

        self.save()
            
    def load_elf(self, fname, load_segments=True, load_symbols=True, group=None):
        #add group
        if group is None or len(group) == 0:
            if group != "global" and group not in self.cfg["segment_groups"]:
                group = os.path.basename(fname)
                if not self.group_add(group):
                    self.error("Could not create group %s" % group)
                    return False

        if group == "global" and load_segments:
            self.error("Can not load segments to global group")
            return False
                
        e = elfloader(fname)

        #load sections
        if load_segments:
            for segment in e.iter_segments():
                    vaddr = segment["vaddr"]
                    size = segment["size"]
                    data = segment["data"]
                    name = "Segment_0x%x" % (vaddr)
                    if not self.add_segment(group, name, vaddr, data, size):
                        self.error("Failed to add segment %s" % name)
                        return False

        #symbols
        if load_symbols:
            for symbol in e.iter_symbols():
                self.add_symbol(group, symbol["name"], symbol["value"])

            self.save()

    def load_core(self, fname, load_segments=True, load_symbols=True, group=None):
        f = open(fname, "rb")
        elf = elffile.ELFFile(f)

        #add group
        if group is None or len(group) == 0:
            if group != "global" and group not in self.cfg["segment_groups"]:
                group = os.path.basename(fname)
                if not self.group_add(group):
                    self.error("Could not create group %s" % group)
                    return False

        if group == "global" and load_segments:
            self.error("Can not load segments to global group")
            return False
                

        #load sections
        if load_segments:
            for segment in elf.iter_segments():
                if segment.header.p_type == 'PT_LOAD':
                    vaddr = segment.header.p_vaddr
                    size = segment.header.p_memsz
                    data = segment.data()
                    name = "Segment_0x%x" % (vaddr)
                    if not self.add_segment(group, name, vaddr, data, size):
                        self.error("Failed to add segment %s" % name)
                        return False

        #symbols
        if load_symbols:
            for section in elf.iter_sections():
                if section.header.sh_type in ['SHT_SYMTAB', 'SHT_DYNSYM']:
                    for symbol in section.iter_symbols():
                        name = symbol.name
                        value = symbol.entry["st_value"]
                        typ = symbol.entry["st_info"]["type"] # STT_NOTYPE STT_FUNC STT_FILE
                        #print (typ, name, value)
                        self.add_symbol(group, name, value)

                if section.header.sh_type in ['SHT_NOTE']:
                    for note in section.iter_notes():
                        if note.n_type == "NT_FILE":
                            print("found NT_FILE")
                            for fname, desc in zip(note["n_desc"]["filename"],  note["n_desc"]["Elf_Nt_File_Entry"]):
                                print(fname, desc)



            self.save()



    def load_idb(self, fname, load_segments=False, load_functions=True):
        import idb
        with idb.from_file(fname) as db:
            api = idb.IDAPython(db)

            #load segments
            if load_segments:
                for addr in api.idautils.Segments():
                    try:
                        end = api.idaapi.get_segm_end(addr)
                        size = end-addr
                        data = api.ida_bytes.get_bytes(addr, size) #seems to fail sometimes
                        name = api.idaapi.get_segm_name(addr)
                        name = "%s_%s_0x%x" % (os.path.basename(fname), name, addr)
                        print(name)
                        self.add_segment(group, name, addr, data, size)
                    except:
                        import traceback; traceback.print_exc()

            #extract function names
            if load_functions:
                for addr in api.idautils.Functions():
                    name = api.idc.GetFunctionName(addr)
                    if self.cfg["config"]["thumb_mode"]:
                        addr |= 1

                    self.add_symbol("global", name, addr)

            #vs vstruct

        self.save()

    """
    Config manipulation
    """
    def set_toolchain(self, toolchain):
        if find_executable(toolchain+"gcc") is None:
            self.error("could not find command %sgcc" % toolchain)
            return False

        if find_executable(toolchain+"ld") is None:
            self.error("could not find command %sld" % toolchain)
            return False

        self.cfg["config"]["TOOLCHAIN"] = toolchain

        return True

    def set_emulation_config(self, cflags, code_base):
        if self.is_valid_addr(code_base): 
            self.error("EMULATION_CODE_BASE 0x%0x already mapped" % code_base)
            return False

        self.cfg["config"]["EMULATION_CFLAGS"] = cflags
        self.cfg["config"]["EMULATION_CODE_BASE"] = code_base

        return True

    def set_patch_config(self, cflags, code_base):
        self.cfg["config"]["PATCH_CFLAGS"] = cflags
        self.cfg["config"]["PATCH_CODE_BASE"] = code_base

        return True

    """
    Group manipulation
    """
    def group_add(self, name):
        if name in self.cfg["segment_groups"] or name == "global":
            self.error("Group %s already exists" % name)
            return False

        if "/" in name:
            self.error("Group name %s contains invalid characters" % name)
            return False

        group_path = os.path.join(self.path, "segment_groups", name)
        if os.path.exists(group_path):
            self.error("Group path %s already exists" % group_path)
            return False
            

        group = {"active":True, "symbols":{}, "segments":{}}
        self.cfg["segment_groups"][name] = group
        os.mkdir(group_path)
        self.save()
        return True

    def get_group_path(self, group):
        if group not in self.cfg["segment_groups"]:
            self.error("Group %s does not exist" % (group))
            return False

        group_path = os.path.join(self.path, "segment_groups", group)
        if not os.path.exists(group_path):
            self.error("Group path %s does not exists" % group_path)
            return False

        return group_path

    def group_update(self, old_group, new_group):
        if old_group not in self.cfg["segment_groups"]:
            self.error("Group %s does not exist" % (old_group))
            return False

        if old_group == new_group:
            return True

        if new_group in self.cfg["segment_groups"]:
            self.error("Group %s already exist" % (new_group))
            return False

        old_path = self.get_group_path(old_group)
        if not old_path:
            self.error("Could not get path for group %s" % (new_group))
            return False

        if not self.group_add(new_group):
            self.error("Could not add group" % (new_group))
            return False

        new_path = os.path.join(self.path, "segment_groups", new_group)
        os.rmdir(new_path)
        shutil.move(old_path, new_path)
        group = self.cfg["segment_groups"][old_group]
        del self.cfg["segment_groups"][old_group]
        self.cfg["segment_groups"][new_group] = group
        return True

    def group_delete(self, group):
        if group not in self.cfg["segment_groups"]:
            self.error("Group %s does not exist" % (group))
            return False

        path = self.get_group_path(group)
        if not path:
            self.error("Could not get path for group %s" % (group))
            return False

        for segment_name in list(self.cfg["segment_groups"][group]["segments"].keys()):
            self.delete_segment(group, segment_name)

        del self.cfg["segment_groups"][group]
        try:
            os.rmdir(path)
        except:
            self.error("Could not remove directory %s" % path)
        self.save()

        return True

    def group_set_active(self, group, value=True):
        if group not in self.cfg["segment_groups"]:
            self.error("Group %s does not exist" % (group))
            return False

        self.cfg["segment_groups"][group]["active"] = value
        return True

    def group_deactivate_all(self):
        for groupName in self.cfg["segment_groups"]:
            self.cfg["segment_groups"][groupName]["active"] = False

        return True


    """
    Segment manipulation
    """
    def add_segment(self, group, name, addr, data, size=0):
        if name == "":
            name = "Segment_0x%x" % addr
        else:
            name = os.path.basename(name)

        if size % 8 != 0:
            size += 8-(size % 8)

        if size > 0 and len(data) < size:
            data += b"\0" * (size - len(data))

        if len(data) == 0:
            self.error("Empty segment %s" % name)
            return False

        if group not in self.cfg["segment_groups"]:
            self.error("Group %s does not exist" % group)
            return False

        if group == "global":
            self.error("Global group can not contain segments")
            return False

        group_path = self.get_group_path(group)
        if not group_path:
            self.error("Could not get group path")
            return False

        segment_path = os.path.join(group_path, name+".bin")
        if os.path.exists(segment_path):
            self.error("Segment path %s already exists" % group_path)
            return False
            
        segment = {}
        segment["addr"] = int(addr)
        segment["size"] = len(data)
        segment["active"] = True

        with open(segment_path, "wb") as f:
            f.write(data)

        self.cfg["segment_groups"][group]["segments"][name] = segment
        self.save()

        return True

    def get_segment_path(self, group, name):
        group_path = self.get_group_path(group)
        if not group_path:
            self.error("Could not get group path")
            return False

        if name not in self.cfg["segment_groups"][group]["segments"]:
            self.error("Segment %s in %s does not exist" % (name, group))
            return False

        segment_path = os.path.join(group_path, name+".bin")
        if not os.path.exists(segment_path):
            self.error("Segment path %s does not exist" % group_path)
            return False

        return segment_path

    def update_segment(self, old_group, old_name, new_group, new_name, addr):
        old_path = self.get_segment_path(old_group, old_name)
        if not old_path:
            self.error("Could not get old segment path")
            return False

        new_group_path = self.get_group_path(new_group)
        if not new_group_path:
            self.error("Could not get new group path")
            return False

        if new_group not in self.cfg["segment_groups"]:
            self.error("Group %s does not exist" % (new_group))
            return False

        if old_name != new_name or old_group != new_group:
            if new_name in self.cfg["segment_groups"][new_group]["segments"]:
                self.error("Segment %s in %s already exist" % (name, group))
                return False

            new_path = os.path.join(new_group_path, new_name+".bin")
            print(old_path, new_path)
            shutil.move(old_path, new_path)

        segment = self.cfg["segment_groups"][old_group]["segments"][old_name]
        del self.cfg["segment_groups"][old_group]["segments"][old_name]
        segment["addr"] = addr
        self.cfg["segment_groups"][new_group]["segments"][new_name] = segment
        self.save()

        return True


    def delete_segment(self, group, name):
        path = self.get_segment_path(group, name)
        if not path:
            self.error("Could not get segment path")
            return False

        del self.cfg["segment_groups"][group]["segments"][name]
        try:
            os.unlink(path)
        except:
            self.error("Could not unlink %s" % path)
        self.save()

    def set_active_segment(self, group, name, value):
        if group not in self.cfg["segment_groups"]:
            self.error("Group %s does not exist" % (group))
            return False

        if name not in self.cfg["segment_groups"][group]["segments"]:
            self.error("Segment %s in %s does not exist" % (name, group))
            return False
        self.cfg["segment_groups"][group]["segments"][name]["active"] = value
        

    def is_valid_addr(self, addr, group="global"):
        if group != "global" and group not in self.cfg["segment_groups"]:
            self.error( "Group %s does not exist" % group)
            return False

        if group == "global":
            for g in self.cfg["segment_groups"]:
                #ignore non active groups
                if not self.cfg["segment_groups"][g]["active"]:
                    continue

                #search segment list
                for segment in self.cfg["segment_groups"][g]["segments"].values():
                    if addr >= segment["addr"] and addr <= segment["addr"] + segment["size"] and segment["active"]:
                        return True

        else:
            #search group
            for segment in self.cfg["segment_groups"][group]["segments"].values():
                if addr >= segment["addr"] and addr <= segment["addr"] + segment["size"] and segment["active"]:
                    return True

        return False
    
    """
    Symbols
    """
    def add_symbol(self, group, name, addr):
        if name == "" or "$" in name or "." in name:
            self.error("Invalid symbol name %s" % name)
            return False

        if name in symbol_name_blacklist:
            self.error("Symbol %s renamed __imported__%s" % (name, name))
            name = "__imported__"+name

        #if not self.is_valid_addr(addr, group=group):
        #    self.error( "Symbol %s (0x%x) in no segment" % (name, addr))
        #    return False

        if group != "global" and group not in self.cfg["segment_groups"]:
            self.error( "Group %s does not exist" % group)
            return False

        symbol_table = self.cfg["symbols"] if group == "global" else self.cfg["segment_groups"][group]["symbols"]

        if name in symbol_table:
            self.error("Symbol %s already exists" % name)
            return False

        symbol_table[name] = addr

        return True

    def delete_symbol(self, group, name):
        if group != "global" and group not in self.cfg["segment_groups"]:
            self.error("Group %s does not exist" % group)
            return False

        symbol_table = self.cfg["symbols"] if group == "global" else self.cfg["segment_groups"][group]["symbols"]
        if name not in symbol_table:
            self.error("Symbol %s does not exists" % name)
            return False

        del symbol_table[name]

        return True

    def update_symbol(self, old_group, old_name, new_group, new_name, addr):
        if not self.delete_symbol(old_group, old_name):
            self.error( "Failed to remove symbol %s in group %s" % (old_name, old_group))
            return False

        if not self.add_symbol(new_group, new_name, addr):
            self.add_symbol(old_group, old_name, addr)
            self.error( "Failed to add symbol %s in group %s" % (new_name, new_group))
            return False


        return True

    def get_symbols(self):
        symbols = {}
        for name, addr in self.cfg["symbols"].items():
            symbols[name] = addr

        for segment_group in self.cfg["segment_groups"]:
            if self.cfg["segment_groups"][segment_group]["active"]:
                for name, addr in self.cfg["segment_groups"][segment_group]["symbols"].items():
                    symbols[name] = addr

        return symbols

    def symbolize(self, addr):
        next_symbol = str(addr)
        next_addr = 0
        for name, x in self.get_symbols().items():
            if addr == x:
                return name

            #get symbol with offset, e.g. functions
            if addr > x and x > next_addr:
                next_symbol = "%s + 0x%x" % (name, addr - x) 
                next_addr = x

        return next_symbol


    """
    Create build scripts
    """
    def create_build_scripts(self):
        self.create_symbol_scripts()
        self.create_ldscripts()
        self.create_makefile()
        return True

    def create_symbol_scripts(self):
        symbols_defined = {}
        ld = open("%s/gen/symbols.ld" % self.path, "w")
        h = open("%s/gen/frankenstein_config.h" % self.path, "w")

        #Symbols for active groups
        for group in sorted(self.cfg["segment_groups"].keys()):
            #skip non active groups
            if not self.cfg["segment_groups"][group]["active"]:
                continue

            symbols = self.cfg["segment_groups"][group]["symbols"]
            for name in sorted(symbols.keys()):
                addr = symbols[name]
                if name not in symbols_defined:
                    ld.write("%s = 0x%x;\n" % (name, addr))
                    h.write("#define FRANKENSTEIN_HAVE_%s\n" % name)
                    symbols_defined[name] = group
                else:
                    self.error("Symbol %s in group %s already defined in group %s" % (name, group, symbols_defined[name]))

        #Global Symbols
        for name in sorted(self.cfg["symbols"].keys()):
            addr = self.cfg["symbols"][name]
            if name not in symbols_defined:
                ld.write("%s = 0x%x;\n" % (name, addr))
                h.write("#define FRANKENSTEIN_HAVE_%s\n" % name)
                symbols_defined[name] = "global"
            else:
                self.error("Symbol %s in global already defined in group %s" % (name, symbols_defined[name]))

        ld.close()
        h.close()

    def create_ldscripts(self):
        memory_ld = ""
        sections_ld = ""

        #iterate over groups
        for group in sorted(self.cfg["segment_groups"].keys()):
            #skip non active groups
            if not self.cfg["segment_groups"][group]["active"]:
                continue

            #collect segments
            segments = self.cfg["segment_groups"][group]["segments"]
            for name in segments:
                if not segments[name]["active"]:
                    continue
                addr = segments[name]["addr"]
                size = segments[name]["size"]

                memory_ld += "  %s (rwx)  : ORIGIN = 0x%x, LENGTH = 0x%x\n" % (name, addr, size)
                sections_ld += "  .%s 0x%x:{ gen/%s/%s.segment.o} > %s\n" % (name, addr, group, name, name)

        #define where to put the actual code
        sections_ld += "  .text 0x%x:{ gen/src.o (.text)}\n" %  self.cfg["config"]["EMULATION_CODE_BASE"]
        sections_ld += "  .data ALIGN(LOADADDR(.text)+SIZEOF(.text), 0x1000):{ * (*)}\n"

        with open("%s/gen/segments.ld" % self.path, "w") as f:
            f.write("INCLUDE gen/symbols.ld;\n")
                
            f.write("ENTRY(_start);\n")
            f.write("MEMORY {\n%s}\n" % memory_ld)
            f.write("SECTIONS {\n%s}\n" % sections_ld)

        with open("%s/gen/patch.ld" % self.path, "w") as f:
            f.write(patch_ld %  self.cfg["config"]["PATCH_CODE_BASE"])

    def create_makefile(self):
        with open("%s/Makefile" % self.path, "w") as f:
            for key,value in self.cfg["config"].items():
                if isinstance(value, int):
                    f.write("%s=0x%x\n" % (key, value))
                else:
                    f.write("%s=%s\n" % (key, value))

            f.write(makefile)

    """
    Sanity Check
    """
    def sanity_check(self, autofix=False):
        ret = True
        if not self.check_symbols():
            ret = False

        if not self.check_segments():
            ret = False

        if not self.check_files():
            ret = False

        if not self.check_toolchain():
            ret = False

        return ret


    def check_symbols(self, autofix=False):
        ret = True
        #global symbols
        for name, addr in self.cfg["symbols"].items():
            if not self.is_valid_addr(addr):
                self.error ("Symbol %s of group global in no segment" % name)
                ret = False
                if autofix:
                    self.error ("Deleting broken symbol")
                    self.delete_symbol("global", name)

        for group in self.cfg["segment_groups"]:
            for name, addr in self.cfg["segment_groups"][group]["symbols"].items():
                if not self.is_valid_addr(addr):
                    self.error ("Symbol %s of group %s in no segment" % (name, group))
                    ret = False
                    if autofix:
                        self.error ("Deleting broken symbol")
                        self.delete_symbol(group, name)

        if autofix:
            self.save()

        return ret

    def check_segments(self, autofix=False):
        active_segments = [] #group, name, start, size
        ret = True

        #iterate over groups
        for group_name in self.cfg["segment_groups"]:
            #skip non active groups
            if not self.cfg["segment_groups"][group_name]["active"]:
                continue

            #collect segments
            segments = self.cfg["segment_groups"][group_name]["segments"]
            for segment_name in segments:
                if not segments[segment_name]["active"]:
                    continue

                start = segments[segment_name]["addr"]
                size = segments[segment_name]["size"]
                end = start + size - 1

                #check for overlapping segments
                for gn,sn,st,sz in active_segments:
                    e = st + sz - 1
                    if start <= st and end >= st:
                        self.error("Segment %s from group %s overlaps with %s from %s" %(segment_name, group_name, sn, gn))
                        ret = False
                        continue
                    if start <= e and end >= e:
                        self.error("Segment %s from group %s overlaps with %s from %s" %(segment_name, group_name, sn, gn))
                        ret = False
                        continue
                    if start >= st and start <= e:
                        self.error("Segment %s from group %s overlaps with %s from %s" %(segment_name, group_name, sn, gn))
                        ret = False
                        continue
                    if end >= st and end <= e:
                        self.error("Segment %s from group %s overlaps with %s from %s" %(segment_name, group_name, sn, gn))
                        ret = False
                        continue

                active_segments += [[group_name, segment_name, start, size]]

        return ret

    def check_files(self, autofix=False):
        ret = True
        for group_name in self.cfg["segment_groups"]:
            #skip non active groups
            if not self.cfg["segment_groups"][group_name]["active"]:
                continue

            if not self.get_group_path(group_name):
                ret = False
                self.error("Directory for group %s does not exist" % group_name)

            #collect segments
            segments = self.cfg["segment_groups"][group_name]["segments"]
            for segment_name in segments:
                if not segments[segment_name]["active"]:
                    continue

                if not self.get_segment_path(group_name, segment_name):
                    ret = False
                    self.error("File for segment %s in group %s does not exist" % (segment_name, group_name))

            return ret

    def check_toolchain(self):
        toolchain = self.cfg["config"]["TOOLCHAIN"]

        if find_executable(toolchain+"gcc") is None:
            self.error("could not find command %sgcc" % toolchain)
            return False

        if find_executable(toolchain+"ld") is None:
            self.error("could not find command %sld" % toolchain)
            return False

        return True

    """
    Debug
    """
    def show(self):
        for group_name in self.cfg["segment_groups"]:
            print("Group %s, Symbols: %d, Active:%s " %  
                (   group_name, 
                    len(self.cfg["segment_groups"][group_name]["symbols"]),
                    self.cfg["segment_groups"][group_name]["active"]) )

            for group_name in self.cfg["segment_groups"]:
                segments = self.cfg["segment_groups"][group_name]["segments"]
                for segment_name in segments:
                    print(segment_name, self.cfg["segment_groups"][group_name]["segments"][segment_name])

            print()




if __name__ == "__main__":
    import sys
    p = Project(sys.argv[1])
    #print(p.symbolize(int(sys.argv[2],16)))
    #p.load_symbol_csv(sys.argv[2], "global")
    #name = "Nexus 5 Bluetooth"
    #os.system("rm -rf /tmp/test_project")

    #p = Project("/tmp/test_project")
    ##p.load_elf("../gen/mempatch", load_symbols=False)
    p.load_core(sys.argv[2], load_segments=False, group="global")
    #p.load_idb(sys.argv[2])
    p.save()

    #p.create_build_scripts()

    #with open("%s/src/test.c" % p.path, "w") as f:
    #    f.write("extern void cont(); void _start() {cont();}")
        
    #p.load_symbol_csv(sys.argv[2])
    #p.create_build_scripts()
