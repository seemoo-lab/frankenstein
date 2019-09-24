import sys
from elftools.elf import elffile
from unicorn import *
from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_ARM, arm_const
from binascii import hexlify, unhexlify
import struct
from subprocess import Popen, PIPE, STDOUT
from random import getrandbits
import angr
import re
import json

class emu:
    """
    Loads ELF file to unicorn, sets watchpoints and stdin
    """
    def __init__(self, fname, stdin, watchpoints=[], drcov=True):
        self.stdin = stdin
        self.exception = ""
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.fname = fname
        self.fd = open(fname, "rb")
        self.elf = elffile.ELFFile(self.fd) 

        self.symbols = {}
        self.symbols_reverse = {}
        for i in xrange(self.elf.num_sections()):
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

        #loading prog headrs
        self.state = []
        for i in xrange(self.elf.num_segments()):
            s = self.elf.get_segment(i)
            if s.header["p_type"] == "PT_LOAD":
                addr = s.header["p_vaddr"]
                data = s.data()
                size = s.header["p_memsz"]
                print "loading", hex(addr), size
                self.uc.mem_map(addr, self.pagreesize(size), UC_PROT_ALL)
                self.uc.mem_write(addr, data)
                self.state += [(addr, size, data)]



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

    def pagreesize(self, s):
        if s % 4096 == 0:
            return s
        return ((s / 4096) + 1) * 4096

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
                        self.stderr += data
                        sys.stderr.write(data)
                    #sys.stdout.write(str(data))
                else:
                    print "unknown intr"

    """
    Implement memory and code watchpoints
    """
    @staticmethod
    def hook_bb(uc, address, size, self):
        if address >= 0xbeee000 and address < 0xbeef000 + 0x80000: #XXX
            return
        self.coverage_bb.add((address, size))

    @staticmethod
    def hook_code(uc, address, size, self):
        if address >= 0xbeee000 and address < 0xbeef000 + 0x80000: #XXX
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
        if pc >= 0xbeee000 and pc < 0xbeef000 + 0x80000: #XXX
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
    def trace_state_change(self, reason):
        print reason
        new_state = []
        memdiff = []
        for addr, size, data in self.state:
            new_data = self.uc.mem_read(addr, size)
            new_data = map(chr, new_data)
            if data != new_data:
                new = old = ""
                for i in xrange(len(data)):
                    if data[i] != new_data[i]:
                        old += hexlify(data[i])
                        new += hexlify(new_data[i])
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
            new_data = map(chr, new_data)
            current_offset = 0

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
                    for i in xrange(block_size):
                        if new_row[i] == old_row[i]:
                            hex_new += "%02x " % ord(new_row[i])
                            hex_old += "   "
                        else:
                            hex_new += "\033[;32m%02x\033[;00m " % ord(new_row[i])
                            hex_old += "\033[;31m%02x\033[;00m " % ord(old_row[i])

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
            print "runing until exit @ 0x%x" % self.symbols["exit"]
            self.uc.emu_start(self.elf.header.e_entry, self.symbols["exit"], timeout=timeout*UC_SECOND_SCALE)
            self.trace_state_change("Exit")
        except KeyboardInterrupt:
            sys.exit(1)
        except Exception as e:
            self.exception = str(e)
            print e
            import traceback; traceback.print_exc()
            print hex(self.uc.reg_read(arm_const.UC_ARM_REG_PC))
            self.trace_state_change(str(e))

    def run_qemu(self):
        prefix = "t-%016x" % getrandbits(64)
        cmd = ["qemu-arm", "-trace", "translate_block,file=%s" % prefix, self.fname]
        p = Popen(cmd)
        p.communicate()

        print "angr"
        a = angr.Project(self.fname, auto_load_libs=False)
        print "tracefile"
        with open(prefix, "r") as f:
            for line in f:
                try:
                    pc = re.findall("pc:0x[0-9a-f]*",line)[0][3:]
                    pc = int(pc, 16)
                    if pc < 0xbeee000:
                        size = a.factory.block(pc+1).size
                        self.coverage_bb.add((pc, size))
                        
                except:
                    import traceback; traceback.print_exc()
                    pass

        print "qemu done"

    def get_drcov(self):
        drcov = "DRCOV VERSION: 2\nDRCOV FLAVOR: drcov\n"

        drcov += "Module Table: version 2, count %d\n" % len(self.state)
        drcov += "Columns: id, base, end, entry, path\n"
        for i in xrange(len(self.state)):
            addr, size, _ = self.state[i]
            drcov += "%d, 0x%x, 0x%x, 0x%x, %s\n" % (i, addr, addr+size+1, addr, "execute.exe")

        drcov += "BB Table: %d bbs\n" % len(self.coverage_bb)
        for address, size in self.coverage_bb:
            for module_id in xrange(len(self.state)):
                base_addr, module_size, _ = self.state[module_id]
                if address >= base_addr and address <= base_addr + module_size:
                    break

            drcov += struct.pack("<I", address - base_addr)
            drcov += struct.pack("<h", size)
            drcov += struct.pack("<h", module_id)

        return drcov




if __name__ == "__main__":
    #e = emu(sys.argv[1], sys.stdin.read(), map(lambda x: int(x, 16), sys.argv[2:]))
    #e.run()

    
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
        print coverage
        coverage = map(lambda x: (x, a.factory.block(x+1).size), coverage)
        e.coverage_bb = coverage

    with open("coverage.drcov", "w") as f:
        f.write(e.get_drcov())
    sys.exit()
        
