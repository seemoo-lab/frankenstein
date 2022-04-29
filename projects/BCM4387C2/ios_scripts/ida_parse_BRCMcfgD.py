# Parse BRCMcfgD data
# written for IDA 7.6
# jiska
# tested with iPhone 12 + Galaxy S10e Bluetooth firmware (not all exceptions work on S10e, though)
# format reversing see https://naehrdine.blogspot.com/2021/01/broadcom-bluetooth-unpatching.html

import idc
import idautils
import idaapi
import ida_bytes
import ida_funcs

CFG_START = 0x00240000  # section for config, identify by searching for "BRCMcfgS" string

def search_function():

    # has to start with `BRCMcfgS`
    start_string = ida_bytes.get_strlit_contents(CFG_START, -1, idc.STRTYPE_C)
    assert start_string.decode() == 'BRCMcfgS', "Invalid BRCMcfgS section."

    # S10e + iPhone 12 have config data at offset 0x42, use static offset for now
    config_string = ida_bytes.get_strlit_contents(CFG_START + 0x42, -1, idc.STRTYPE_C)
    assert config_string.decode() == 'BRCMcfgD', "Invalid BRCMcfgD section."

    # total length at offset 0x4e
    config_length = ida_bytes.get_32bit(CFG_START + 0x4E)
    print(f"Config length: {config_length}")

    # first entry at 0x52
    curr_addr = CFG_START + 0x52
    end = CFG_START + config_length - 1

    # iterate over whole config
    while curr_addr < end:
        # sanity check
        if curr_addr == idc.BADADDR:
            break

        # parse 3 byte entry header
        entry_type = ida_bytes.get_16bit(curr_addr)
        entry_len = ida_bytes.get_byte(curr_addr + 2)

        # main parser
        # types as defined in configdef20739B1.hdf etc.
        print(f"v-- {curr_addr:#08x}")

        if entry_type == 0x0303:
            config_name = ida_bytes.get_strlit_contents(curr_addr + 3, entry_len, idc.STRTYPE_C).decode()
            print(f"Local Name: {config_name}")

        # Patch Entry
        # first entry on iPhone 12: 0x243874
        elif entry_type == 0x0110:
            patch_index = ida_bytes.get_byte(curr_addr + 3)
            block_addr  = ida_bytes.get_32bit(curr_addr + 4)
            repl_instr  = ida_bytes.get_32bit(curr_addr + 8)

            # if the replacement instruction also needs a function
            # in the patchram region, the following will be set,
            # otherwise zero
            code_size   = ida_bytes.get_16bit(curr_addr + 12)
            code_addr   = ida_bytes.get_32bit(curr_addr + 14)
            code_value  = ida_bytes.get_bytes(curr_addr + 18, code_size)


            print(f"Patch Entry: #{patch_index:#03d}, src: {block_addr:#08x}, patch_dst: {code_addr:#08x}")

            # if the patch entry refers to a function, create
            # an offset and also create the function
            if code_addr != 0:
                # create new function
                ida_funcs.add_func(code_addr, idc.BADADDR)
                # source is only sometimes a function so we don't create one there...

                # add a reference to fix xrefs
                idc.op_plain_offset(curr_addr + 14, 0, 0)
                idc.op_plain_offset(curr_addr + 4, 0, 0)

                # set some helpful names
                idc.set_name(curr_addr + 14, f"patch_rom_entry_{patch_index}")
                idc.set_name(curr_addr + 4, f"patch_ram_entry_{patch_index}")
                #idc.set_name(block_addr, f"patch_{patch_index}") # nope, might already be named...



        # Data field.
        elif entry_type == 0x0103:
            addr = ida_bytes.get_32bit(curr_addr + 3)
            data_len = ida_bytes.get_16bit(curr_addr + 7)

            # somehow the first entry has a larger address and seems to be invalid
            # the same is the case later, if the first byte is 01 in the entry.
            # definitely different than described in hdf...
            # entry can be:
            #    len
            #    offset (optional)
            #    addr, starting with 0x00 in reverse byte order

            if addr > 0xffffff:
                data_offset = ida_bytes.get_byte(curr_addr + 3)
                addr = (addr & 0xffffff00) >> 8
                print(f"Data field has offset {data_offset:#04x}.")

                # FIXME offset handling is a bit undeterministic...
                if data_offset == 0x01:
                    entry_len += 1          # fix offset
                    addr = addr & 0xffffff  # fix address by removing first byte
                if data_offset == 0x09:
                    # f4 09 -> 0x4f8
                    # 84 09 -> 0x488
                    # then subtract 3 because we add it later
                    entry_len = ((((entry_len & 0xf0) >> 4) + ((entry_len & 0x0f) << 4)) << 4) + 8 - 3
                if data_offset == 0x08 and curr_addr < 0x00241D28:
                    # FIXME
                    # at 0x2418f4
                    # b0 08 -> 0x434
                    entry_len = 0x434 - 3
                if data_offset == 0x0e and curr_addr < 0x00242542:
                    # FIXME
                    # at 0x241e0a
                    # b4 0e -> 0x738
                    entry_len = 0x738 - 3
                if data_offset == 0x02:
                    # FIXME
                    # at 0x24349C
                    # 80 02 -> 0x104
                    # at 0x2435A0
                    # 80 02 -> 0x104
                    print(f"data offset 2, entry len {entry_len:#04x}")
                    if entry_len == 0x80:
                        entry_len = 0x104 - 3



            print(f"Data: {addr:#08x}, entry length {entry_len:#08x}") #, data length {data_len:#08x}")
            #print(f"   Next entry: {curr_addr + entry_len + 3:#08x} / {curr_addr + data_len:#08x}")

        elif entry_type == 0x0106:
            address = ida_bytes.get_32bit(curr_addr + 3)
            print(f"Function Call: {address:#08x}")

            # create new function
            ida_funcs.add_func(address, idc.BADADDR)
            # add a reference to fix xrefs
            idc.op_plain_offset(curr_addr + 3, 0, 0)

        elif entry_type == 0x0102:
            print(f"Init BB Register Bit Fields")

        elif entry_type == 0x0304:
            print(f"AFH Channel Classification Configuration")

        elif entry_type == 0x0305:
            print(f"AFH Channel Classification Internal Configuration")

        elif entry_type == 0x01F0:
            print(f"PMU register w/r")

            # additional offset stored in the record subtype, which is only one byte (1, 2, 3)
            # within a 32-bit field. the offset is optional.
            if ida_bytes.get_byte(curr_addr + 4) != 0:
                entry_len += 0x100          # fix offset
                # TODO this one breaks on S10e

        elif entry_type == 0x0700:
            print(f"Temperature Correction Algorithm Config")

        elif entry_type == 0x0701:
            print(f"TCA Table")


        # print general information for unkown patches
        elif entry_type != 0 and entry_len != 0:
            print(f"Type {entry_type:#04x}, length {entry_len:#08x}")

        # advance to next entry, length does not include 3 byte entry header
        curr_addr = curr_addr + 3 + entry_len

search_function()