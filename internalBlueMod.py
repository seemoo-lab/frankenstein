import internalblue.cmds
from internalblue.cmds import log, auto_int
import internalblue.cli
import internalblue.hci as hci
import argparse
import traceback
from elftools.elf import elffile
from elftools.elf.constants import SH_FLAGS
from pwn import *

from datetime import datetime
import struct
from binascii import *
import time
import os
from threading import Timer

#frankenstein project core
from core.project import Project

symbols = {}

CmdLoadELFInitialized = False
class CmdLoadELF(internalblue.cmds.Cmd):
    keywords = ["loadelf"]
    description = "Loads an ELF file to device and executes entry point"

    parser = argparse.ArgumentParser(prog=keywords[0], description=description)

    parser.add_argument("fname", help="ELF file to load")

    msg = ""

    """
        Loads Sections from ELF file to firmware
        Loads symbols into global dict
        Executes entry point of ELF on behalf
    """
    def load_ELF(self, fname):
        try:
            fd = open(fname, "rb")
            self.elf = elffile.ELFFile(fd)
        except:
            traceback.print_exc()
            log.warn("Could not parse ELF file...")
            return False

        if "_fini" in symbols:
            fini = symbols["_fini"]
            if yesno("Found _fini of already installed patch at 0x%x. Execute?" % fini):
                self.launchRam(fini-1)

        #load sections
        for i in range(self.elf.num_sections()):
            section = self.elf.get_section(i)
            if section.header["sh_flags"] & SH_FLAGS.SHF_ALLOC != 0:
                addr = section.header["sh_addr"]
                name = section.name

                #NOBITS sections contains no data in file
                #Will be initialized with zero
                if section.header["sh_type"] == "SHT_NOBITS":
                    data = b"\x00" * section.header["sh_size"]
                else:
                    data = section.data()

                log.info("Loading %s @ 0x%x - 0x%x (%d bytes)" % (name, addr, addr+len(data), len(data)))
                #write section data to device
                self.writeMem(addr, data)



        #load symbols
        n = 0
        for i in range(self.elf.num_sections()):
            section = self.elf.get_section(i)
            if section.header.sh_type == 'SHT_SYMTAB':
                for symbol in section.iter_symbols():
                    if symbol.name != "" and "$" not in symbol.name:
                        symbols[symbol.name] =  symbol.entry["st_value"]
                        n += 1
        log.info("Loaded %d symbols" % n)

        return self.elf.header.e_entry

    """
        Print info messages emitted from the firmware
    """
    def debug_hci_callback(self, record):
        hcipkt = record[0]
        if not issubclass(hcipkt.__class__, hci.HCI_Event):
            return

        #We use event code 0xfe for info text messages
        #Buffer messages until a newline is found
        if hcipkt.event_code == 0xfe:
            self.msg += hcipkt.data.decode("utf-8")
            while "\n" in self.msg:
                msg_split = self.msg.split("\n")
                log.info("Firmware says: %s" % msg_split[0])
                self.msg = "\n".join(msg_split[1:])

        #We use event code 0xfd for data
        if hcipkt.event_code == 0xfd:
            log.info("Firmware says: %s" % hexlify(hcipkt.data))

        return



    """
    Command implementation
    """
    def work(self):
        args = self.getArgs()
        if args == None:
            return True

        global CmdLoadELFInitialized
        if not CmdLoadELFInitialized:
            if self.internalblue.fw.FW_NAME == "CYW20735B1":
                self.internalblue.patchRom(0x3d32e, b"\x70\x47\x70\x47")
            self.internalblue.registerHciCallback(self.debug_hci_callback)
            CmdLoadELFInitialized = True


        if not os.path.exists(args.fname):
            log.warn("Could not find file %s" % args.fname)
            return False

        entry = self.load_ELF(args.fname)

        #execute entrypoint
        if entry and entry != 0:
            if yesno("Found nonzero entry point 0x%x. Execute?" % entry):
                self.launchRam(entry-1)

        return entry != False

internalblue.cmds.CmdLoadELF = CmdLoadELF

CmdMapMemoryInitialized = False
class CmdMapMemory(CmdLoadELF):
    keywords = ["mapmemory"]
    description = "Loads an ELF file to device and executes entry point"

    parser = argparse.ArgumentParser(prog=keywords[0], description=description)

    parser.add_argument("start", help="Start address for mapping", type=auto_int)

    watchdog = None

    """
    Map memory events
    """
    def map_memory_hci_callback(self, record):
        hcipkt = record[0]
        if not issubclass(hcipkt.__class__, hci.HCI_Event):
            return

        #State report
        if hcipkt.event_code == 0xfa:
            addr = struct.unpack("I", hcipkt.data[:4])[0]
            if addr == 0xffffffff:
                self.expected_addr = -1
                self.segment_start = -1

            #addr is mapped
            elif addr & 1 == 0:
                if self.expected_addr != addr:
                    if self.expected_addr != -1:
                        print ("Found Map 0x%x - 0x%x" % (self.segment_start, self.expected_addr))

                    self.segment_start = addr
                self.expected_addr = addr + 256
                self.last_addr = addr

            #Not mapped
            else:
                self.last_addr = addr


            if self.watchdog:
                self.watchdog.cancel()
            self.watchdog = Timer(1, self.watchdog_handle)
            self.watchdog.start()

    def watchdog_handle(self):
        log.warn("Firmware died at address 0x%x while mapping memory" % (self.last_addr&0xfffffffe))

    """
    Command implementation
    """
    def work(self):
        args = self.getArgs()
        if args == None:
            return True

        global CmdMapMemoryInitialized
        if not CmdMapMemoryInitialized:
            if self.internalblue.fw.FW_NAME == "CYW20735B1":
                self.internalblue.patchRom(0x3d32e, "\x70\x47\x70\x47")
            self.internalblue.registerHciCallback(self.map_memory_hci_callback)
            self.internalblue.registerHciCallback(self.debug_hci_callback)
            CmdMapMemoryInitialized = True


        patch = "projects/%s/gen/map_memory.patch" % self.internalblue.fw.FW_NAME
        if not os.path.exists(patch):
            log.warn("Could not find file %s" % patch)
            return False

        entry = self.load_ELF(patch)

        start = struct.pack("I", args.start)
        self.last_addr = args.start
        self.writeMem(symbols["map_memory_start"], start)

        self.launchRam(entry-1)

        return entry != False

internalblue.cmds.CmdMapMemory = CmdMapMemory

CmdXmitStateInitialized = False
class CmdXmitState(CmdLoadELF):
    keywords = ["xmitstate"]
    description = "Sets a hook on a function, emmits an executable state and add the dump to frankenstein"

    parser = argparse.ArgumentParser(prog=keywords[0], description=description)

    parser.add_argument("target", help="Target function", type=auto_int)

    """
    Receive state dump
    """
    def xmit_state_hci_callback(self, record):
        hcipkt = record[0]
        if not issubclass(hcipkt.__class__, hci.HCI_Event):
            return

        #State report
        if hcipkt.event_code == 0xfc:
            saved_regs, cont = struct.unpack("II", hcipkt.data[:8])
            if cont != 0:
                log.info("Receiving firmware state: regs@0x%x cont@0x%x" % (saved_regs, cont))
                self.segment_data = []
                self.segments = {}
                self.succsess = True
                self.saved_regs = saved_regs
                self.cont = cont

            else:
                if not self.succsess:
                    return
                log.info("Received fuill firmware state")

                groupName = datetime.now().strftime("internalBlue_%m.%d.%Y_%H.%M.%S")
                self.project = Project("projects/"+self.internalblue.fw.FW_NAME)
                self.project.add_group(groupName)
                self.project.deactivate_all_groups()
                self.project.set_active_group(groupName, True)
                self.project.save()
                self.project.add_symbol(groupName, "cont", self.cont|1)
                self.project.add_symbol(groupName, "get_int", symbols["get_int"])
                self.project.add_symbol(groupName, "set_int", symbols["set_int"])
                self.project.add_symbol(groupName, "saved_regs", self.saved_regs)
                for segment_addr in self.segments:
                    self.project.add_segment(groupName, "", segment_addr, "".join(self.segments[segment_addr]))

                self.project.save()

        if hcipkt.event_code == 0xfb:
            segment_addr,size,current = struct.unpack("III", hcipkt.data[:12])
            self.segment_data += [hcipkt.data[12:]]

            #Check if we have missed an HCI event
            if segment_addr + len(self.segment_data)*128 != current + 128:
                if self.succsess:
                    print( hex(segment_addr), hex(len(self.segment_data)*128), hex( current + 128))
                    log.info("Failed to receive state")
                self.succsess = False
                
            #Fully received memory dumo
            if len(self.segment_data)*128 == size:
                log.info("Received segment 0x%x - 0x%x" % (segment_addr, segment_addr+size))
                self.segments[segment_addr] = self.segment_data
                self.segment_data = []

    """
    Command implementation
    """
    def work(self):
        args = self.getArgs()
        if not args:
            return True

        # Initialize callbacks for xmitstate
        global CmdXmitStateInitialized

        if not CmdXmitStateInitialized:

            # disable uart_SetRTSMode if we know its location
            if self.internalblue.fw.FW_NAME == "CYW20735B1":
                self.internalblue.patchRom(0x3d32e, b"\x70\x47\x70\x47")
            elif self.internalblue.fw.FW_NAME == "CYW20819A1":
                self.internalblue.patchRom(0x2330e, b"\x70\x47\x70\x47")

            # and now let's enable the callbacks
            self.internalblue.registerHciCallback(self.debug_hci_callback)
            self.internalblue.registerHciCallback(self.xmit_state_hci_callback)
            CmdXmitStateInitialized = True


        patch = "projects/%s/gen/xmit_state.patch" % self.internalblue.fw.FW_NAME
        print(patch)
        if not os.path.exists(patch):
            log.warn("Could not find file %s" % patch)
            return False

        entry = self.load_ELF(patch)
        if entry == False:
            log.warn("Failed to load patch ELF %s" % patch)
            return False

        target = struct.pack("I", args.target | 1)
        self.writeMem(symbols["xmit_state_target"], target)

        self.launchRam(entry-1)

        return entry != False

internalblue.cmds.CmdXmitState = CmdXmitState


if __name__ == "__main__":
    internalblue.cli.internalblue_cli(sys.argv[1:])
