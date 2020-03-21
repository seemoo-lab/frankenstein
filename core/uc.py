import sys
from elftools.elf import elffile
from elftools.elf.constants import SH_FLAGS
from unicorn import *
from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_ARM, arm_const
from binascii import hexlify, unhexlify
import struct
from subprocess import Popen, PIPE, STDOUT
from random import getrandbits
import re
import json

class emu:
    """
    Loads ELF file to unicorn, sets watchpoints and stdin
    """
    def __init__(self, fname, stdin, watchpoints=[], drcov=True, emulator_base=None, fw_entry_symbol="cont"):
        self.stdin = stdin
        self.exception = ""
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.fname = fname
        self.fd = open(fname, "rb")
        self.elf = elffile.ELFFile(self.fd) 

        self.symbols = {}
        self.symbols_reverse = {}
        for i in range(self.elf.num_sections()):
            sec = self.elf.get_section(i)
            if sec.name == ".symtab":
                for sym in sec.iter_symbols():
                    self.symbols[sym.name] = sym.entry["st_value"] 
                    self.symbols_reverse[sym.entry["st_value"]] = sym.name

        self.results = []
        self.result_id = 0
        self.coverage_pc = set()
        self.coverage_bb = set()
        self.read = set()
        self.write = set()

        self.coverage_activity = {}
        self.read_activity = {}
        self.write_activity = {}

        self.stdout = ""
        self.stderr = ""

        self.emulator_base_start = None
        self.emulator_base_stop = None
        self.fw_entry = self.symbols[fw_entry_symbol] # ignore everything until that symbol

        #loading prog headrs
        self.state = []
        self.segments = []
        for i in range(self.elf.num_sections()):
            section = self.elf.get_section(i)
            if section.header["sh_flags"] & SH_FLAGS.SHF_ALLOC != 0:
                addr = section.header["sh_addr"]
                size = self.pagreesize(section.header["sh_size"])
                name = section.name

                #NOBITS sections contains no data in file
                #Will be initialized with zero
                if section.header["sh_type"] == "SHT_NOBITS":
                    data = b"\x00" * size
                else:
                    data = section.data()

                print("Loading %s @ 0x%x - 0x%x (%d bytes)" % (name, addr, addr+len(data), len(data)))
                self.uc.mem_map(addr, size, UC_PROT_ALL)
                self.uc.mem_write(addr, data)
                if emulator_base == addr:
                    self.emulator_base_start = emulator_base
                    self.emulator_base_stop = emulator_base + size
                else:
                    self.segments += [(name, addr, size)]
                self.state += [(addr, size, data)]

            self.segments = sorted(self.segments, key=lambda x:x[0])


        #stack
        stack = 0xffff000
        self.uc.mem_map(stack, stack+4096, UC_PROT_ALL)
        self.uc.reg_write(arm_const.UC_ARM_REG_SP, stack + 4096)

        #syscalls
        self.uc.hook_add(UC_HOOK_INTR, self.hook_intr, self)

        #tracing
        self.watchpoints = watchpoints
        self.uc.hook_add(UC_HOOK_CODE, self.hook_code, self)
        self.uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self.hook_mem_access, self)

        #prepare drcov file
        self.drcov = drcov
        if drcov:
            self.uc.hook_add(UC_HOOK_BLOCK, self.hook_bb, self)

    def pagreesize(self, s, pagesize=1024):
        if s % pagesize == 0:
            return s
        return (int(s / pagesize) + 1) * pagesize

    """
    We need to emulate read and write for emulation
    """
    @staticmethod
    def hook_intr(uc, size, self):
        #print hex(uc.reg_read(arm_const.UC_ARM_REG_PC))
        pc = uc.reg_read(arm_const.UC_ARM_REG_PC)
        for name in ["read","write"]:
            if self.symbols[name] <= pc and  self.symbols[name] + 8 >= pc:
                #print name
                if name == "read":
                    fd = uc.reg_read(arm_const.UC_ARM_REG_R0)
                    target = uc.reg_read(arm_const.UC_ARM_REG_R1)
                    size = uc.reg_read(arm_const.UC_ARM_REG_R2)

                    data = self.stdin[:size]
                    self.stdin = self.stdin[size:]

                    uc.mem_write(target, data)
                    self.uc.reg_write(arm_const.UC_ARM_REG_R0, len(data))

                elif name == "write":
                    fd = uc.reg_read(arm_const.UC_ARM_REG_R0)
                    target = uc.reg_read(arm_const.UC_ARM_REG_R1)
                    size = uc.reg_read(arm_const.UC_ARM_REG_R2)

                    data = uc.mem_read(target, size)
                    if fd == 1:
                        self.stdout += data
                    else:
                        self.stderr += data.decode("utf-8")
                        sys.stderr.write(data.decode("utf-8"))
                    #sys.stdout.write(str(data))
                else:
                    print("unknown intr")

    """
    Implement memory and code watchpoints
    """
    @staticmethod
    def hook_bb(uc, address, size, self):
        if self.emulator_base_start is not None:
            if address >= self.emulator_base_start and address < self.emulator_base_stop:
                return
        self.coverage_bb.add((address, size))

    @staticmethod
    def hook_code(uc, address, size, self):
        if address & 0xfffffffe == self.fw_entry & 0xfffffffe:
            self.trace_init_state()

        if self.emulator_base_start is not None:
            if address >= self.emulator_base_start and address < self.emulator_base_stop:
                return

        self.coverage_pc.add(address)
        if address in self.coverage_activity:
            self.coverage_activity[address] += 1
        else:
            self.coverage_activity[address] = 1

        if address in self.watchpoints:
            self.trace_state_change("Execute")

    @staticmethod
    def hook_mem_access(uc, access, address, size, value, self):
        pc = self.uc.reg_read(arm_const.UC_ARM_REG_R15)
        if self.emulator_base_start is not None:
            if pc >= self.emulator_base_start and pc < self.emulator_base_stop:
                return
        if access == UC_MEM_WRITE:
            self.write.add((pc, address, value))
            if address in self.write_activity:
                self.write_activity[address] += 1
            else:
                self.write_activity[address] = 1
        else:
            self.read.add((pc, address))
            if address in self.read_activity:
                self.read_activity[address] += 1
            else:
                self.read_activity[address] = 1
        if address in self.watchpoints:
            if access == UC_MEM_WRITE:
                self.trace_state_change("Write 0x%x" % address)
            else:
                self.trace_state_change("Read 0x%x" % address)


    """
    For each tracepoint that was hit
        Dump Registers
        Do Memory Dump
    """
    def trace_init_state(self):
        self.state = []
        for name, addr, size in self.segments:
            data = self.uc.mem_read(addr, size)
            #data = list(map(chr, data))
            self.state += [(addr, size, data)]
        

    def trace_state_change(self, reason):
        print(reason)
        new_state = []
        memdiff = []
        for addr, size, data in self.state:
            new_data = self.uc.mem_read(addr, size)
            #new_data = list(map(chr, new_data))
            if data != new_data:
                new = old = ""
                for i in range(len(data)):
                    if data[i] != new_data[i]:
                        old += "%02x" % data[i]
                        new += "%02x" % new_data[i]
                    elif new != "":
                        memdiff += [(i+addr-len(new), old, new)]
                        new = old = ""

            new_state += [(addr, size, new_data)]

        #XXX
        memdif_rendered = self.render_mem_diff()
        sys.stderr.write(self.stderr)
        sys.stderr.write("\n"+memdif_rendered+"\n")

        self.state = new_state

        regs = {}
        regs["r0"] = self.uc.reg_read(arm_const.UC_ARM_REG_R0)
        regs["r1"] = self.uc.reg_read(arm_const.UC_ARM_REG_R1)
        regs["r2"] = self.uc.reg_read(arm_const.UC_ARM_REG_R2)
        regs["r3"] = self.uc.reg_read(arm_const.UC_ARM_REG_R3)
        regs["r4"] = self.uc.reg_read(arm_const.UC_ARM_REG_R4)
        regs["r5"] = self.uc.reg_read(arm_const.UC_ARM_REG_R5)
        regs["r6"] = self.uc.reg_read(arm_const.UC_ARM_REG_R6)
        regs["r7"] = self.uc.reg_read(arm_const.UC_ARM_REG_R7)
        regs["r8"] = self.uc.reg_read(arm_const.UC_ARM_REG_R8)
        regs["r9"] = self.uc.reg_read(arm_const.UC_ARM_REG_R9)
        regs["r10"] = self.uc.reg_read(arm_const.UC_ARM_REG_R10)
        regs["r11"] = self.uc.reg_read(arm_const.UC_ARM_REG_R11)
        regs["r12"] = self.uc.reg_read(arm_const.UC_ARM_REG_R12)
        regs["sp"] = self.uc.reg_read(arm_const.UC_ARM_REG_R13)
        regs["lr"] = self.uc.reg_read(arm_const.UC_ARM_REG_R14)
        regs["pc"] = self.uc.reg_read(arm_const.UC_ARM_REG_R15)


        tp = {}
        tp["reason"] = reason
        tp["regs"] = regs
        tp["memdiff"] = memdiff
        tp["memdif_rendered"] = memdif_rendered
        tp["stdout"] = self.stdout
        tp["stderr"] = self.stderr
        tp["resid"] = self.result_id
        self.results += [tp]
        self.stdout = ""
        self.stderr = ""
        self.result_id += 1

        return [{"regs": regs, "memdiff": sorted(memdiff)}]

    def render_mem_diff(self, block_size=32):
        ret  = "----------" + ("-"*(3*block_size+1)) + "\n"
        ret += "         |\n"
        print_dots = False
        for addr, size, data in self.state:
            new_data = self.uc.mem_read(addr, size)
            #new_data = list(map(chr, new_data))
            current_offset = 0
            print(len(data), len(new_data), size)

            #for each hexdump row
            while current_offset <  size:
                old_row = data[current_offset: current_offset+block_size]
                new_row = new_data[current_offset: current_offset+block_size]
                #ugly equal comparison
                equal = True
                for x,y in zip(new_row, old_row):
                    equal = equal and (x==y)

                if not equal:
                    hex_new = "%8x |  " % (addr + current_offset)
                    hex_old = "         |  "
                    symbols = ""

                    #render diff
                    for i in range(block_size):
                        if new_row[i] == old_row[i]:
                            hex_new += "%02x " % new_row[i]
                            hex_old += "   "
                        else:
                            hex_new += "\033[;32m%02x\033[;00m " % new_row[i]
                            hex_old += "\033[;31m%02x\033[;00m " % old_row[i]

                        if (addr + current_offset + i) in self.watchpoints:
                            symbols += "         |  "
                            if len("Watchpoint") < 3*i - 1:
                                symbols += " " * (3*i - len("Watchpoint") - 1)
                                symbols += "\033[;33mWatchpoint ^^\033[;00m\n"
                            else:
                                symbols += "   " * i
                                symbols += "\033[;33m^^ Watchpoint\033[;00m\n"
                        elif (addr + current_offset + i) in self.symbols_reverse:
                            name = self.symbols_reverse[addr + current_offset + i]
                            symbols += "         |  "
                            if len(name) < 3*i - 1:
                                symbols += " " * (3*i - len(name) - 1)
                                symbols += "%s ^^\n" % name
                            else:
                                symbols += "   " * i
                                symbols += "^^ %s\n" % name

                    ret += hex_new + "\n" + hex_old + "\n"
                    if len(symbols) > 1:
                        ret += symbols
                    print_dots = True

                else:
                    if print_dots:
                        print_dots = False
                        ret += "         |\n"
                        ret += "         |" + ("-"*(3*block_size+1)) + "\n"
                        ret += "         |\n"
                    


                current_offset += block_size

        #cleanup end
        split = ret.split("\n")
        if len(split) <= 3:
            return ""
        ret = "\n".join(split[:-3]) + "\n"
        ret += "----------" + ("-"*(3*block_size+1)) + "\n"
        return ret


    """
    Run the Emulation
    """
    def run(self, timeout=300):
        try:
            print("runing until exit @ 0x%x" % self.symbols["exit"])
            self.uc.emu_start(self.elf.header.e_entry, self.symbols["exit"], timeout=timeout*UC_SECOND_SCALE)
            self.trace_state_change("Exit")
        except KeyboardInterrupt:
            sys.exit(1)
        except Exception as e:
            self.exception = str(e)
            print(e)
            import traceback; traceback.print_exc()
            print(hex(self.uc.reg_read(arm_const.UC_ARM_REG_PC)))
            self.trace_state_change(str(e))


    def get_drcov(self):
        drcov = b"DRCOV VERSION: 2\nDRCOV FLAVOR: drcov\n"

        drcov += b"Module Table: version 2, count %d\n" % len(self.state)
        drcov += b"Columns: id, base, end, entry, path\n"
        for i in range(len(self.state)):
            addr, size, _ = self.state[i]
            drcov += b"%d, 0x%x, 0x%x, 0x%x, %s\n" % (i, addr, addr+size+1, addr, b"execute.exe")

        drcov += b"BB Table: %d bbs\n" % len(self.coverage_bb)
        for address, size in self.coverage_bb:
            for module_id in range(len(self.state)):
                base_addr, module_size, _ = self.state[module_id]
                if address >= base_addr and address <= base_addr + module_size:
                    break

            drcov += struct.pack("<I", address - base_addr)
            drcov += struct.pack("<h", size)
            drcov += struct.pack("<h", module_id)

        return drcov




if __name__ == "__main__":
    e = emu(sys.argv[1], sys.stdin.read(), map(lambda x: int(x, 16), sys.argv[2:]))
    e.run()
    sys.exit(0)

    
    e = emu(sys.argv[1], None, [])
    if len(sys.argv) <= 2:
        e.run_qemu()
    else:
        #loading state.json from lmp fuzzer
        with open(sys.argv[2], "r") as f:
            state = json.loads(f.read())
        packets_all, testcases_new_blocks, testcases_most_blocks, testcases_most_blocks_scores, crashes, coverage = state
        a = angr.Project(sys.argv[1], auto_load_libs=False)
        coverage = map(lambda x: x&0xffffffff, coverage)
        coverage = filter(lambda x: x<0xbeee000, coverage)
        print(coverage)
        coverage = map(lambda x: (x, a.factory.block(x+1).size), coverage)
        e.coverage_bb = coverage

    with open("coverage.drcov", "w") as f:
        f.write(e.get_drcov())
    sys.exit()
        
