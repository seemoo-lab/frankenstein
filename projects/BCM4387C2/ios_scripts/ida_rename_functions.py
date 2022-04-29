# Based on rename_functions.py from https://gist.github.com/0xgalz/cce0bfead8458226faddad6dd7f88350
# adapted for 32bit ARM and IDA 7.6 by jiska
# tested with iPhone 12 Bluetooth firmware
# porting guide see: https://hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml

import idc
import idautils
import idaapi
import ida_bytes

FUNCTIONS_REGISTERS = {"debug_print": "r2"}  # iPhone 12/13: 0x267D4


def get_string_for_function(call_func_addr, register):
    """
    :param start_addr: The function call address
    :return: the string offset name from the relevant register
    """
    #print(hex(call_func_addr))
    cur_addr = call_func_addr
    str_func = None
    start_addr = idc.get_func_attr(cur_addr, idc.FUNCATTR_START)  # returns 0xffffffff if no function
    cur_addr = idc.prev_head(cur_addr)
    # go through previous opcodes looking for assignment to the register
    while cur_addr >= start_addr:
        #print(idc.print_insn_mnem(cur_addr))
        #print(idc.print_operand(cur_addr, 0))
        if idc.print_insn_mnem(cur_addr) == "LDR" and idc.print_operand(cur_addr, 0).lower() == register.lower():
            # r2 points to an offset which then points to a string
            str_ref = idc.get_operand_value(cur_addr, 1)
            str_addr = idaapi.get_dword(str_ref)
            str_func = ida_bytes.get_strlit_contents(str_addr, -1, idc.STRTYPE_C)
            if str_func:
                try:
                    return str_func.decode()  # bytes to string
                except:
                    return None
        cur_addr = idc.prev_head(cur_addr)
    return str_func


def is_function_name(cur_func_name):
    """
    :param cur_func_name: the current function name
    :return: True/ False - depends if the name is the default name or auto-generated one,
             Names that were chosen by the user will stay the same
    """
    if cur_func_name.startswith("AutoFunc_"):
        return True
    elif cur_func_name.startswith("sub_"):
        return True
    else:
        return False


def search_function():
    curr_addr = 0x0  # MinEA()
    end = 0x2c7100  # MaxEA()
    current_func_name = ""
    while curr_addr < end:
        if curr_addr == idc.BADADDR:
            break
        elif idc.print_insn_mnem(curr_addr) == 'BL':
            if idc.print_operand(curr_addr, 0) in FUNCTIONS_REGISTERS.keys():
                func_name_addr = get_string_for_function(curr_addr,
                                                        FUNCTIONS_REGISTERS[idc.print_operand(curr_addr, 0)].lower())

                #print(func_name_addr)
                if func_name_addr:
                    try:
                        function_start = idc.get_func_attr(curr_addr, idc.FUNCATTR_START)
                        current_func_name = idc.get_func_name(function_start)
                        #print(hex(function_start))
                        #print(current_func_name)
                        #print(func_name_addr)
                        if is_function_name(current_func_name):
                            idaapi.set_name(function_start, func_name_addr)
                        else:
                            print("Function: ", current_func_name, "was not changed")
                    except:
                        print("failed at address " + hex(curr_addr), "function:", \
                            current_func_name, "call:", idc.print_operand(curr_addr, 0))

        curr_addr = idc.next_head(curr_addr, end)

search_function()