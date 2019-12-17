Porting Frankenstein to a new evaluation board
==============================================

The following notes were taken while porting Frankenstein from *CYW20735B1* to *CYW20819A1*. Importing symbols is
only that straight forward if you can take them from one of the SDKs. 


Build environment
-----------------
* In *InternalBlue*, check that the name in the according firmware file matches.
  In our case it's in `internalblue/fw/fw_0x220c.py`.
* Start *Frankenstein* Web UI: `python2 manage.py runserver`.
  * For whatever reason, `pip` currently seems to install modules non-readable worldwide / for other users ...
    you might need to change file permissions for `pyelftools` to work. (On my system)
* Create a new project named *CYW20819A1*.
* Import symbols if you have some:
  * Get *Modus Toolbox* from *Cypress*. Other evaluation boards might require *WICED Studio* or similar.
  * Symbols are in `~/Documents/ModusToolbox_1.1/libraries/bt_20819A1-1.0/components/BT-SDK/20819-A1_Bluetooth/
    WICED/internal/20819A1/patches/patch.elf`.
  * Click on *Load ELF* and add them.
  * Load *Symbols* and *Segments* to *global*. It is important to set them to *global*, otherwise, these symbols 
    will only apply to one specific memory dump.
     * For me, adding Segments were wrong! The Segments in the `patch.elf` were not useful. 
       Better create a large dummy segment.
     * ... but importing Symbols only worked. 
* Symbols for global variables are not included in `patch.elf`. In *WICED Studio*, they are contained in 
  the files `20719mapb0.h`, `20739mapb0.h` and `20703mapa0.h`. We do not have them in *Modus Toolbox*, but most
  of them stay the same over a long time. So we can carefully copy those variables that we need in the next step for
  compilation.
  Add the following *global* variables via the *Frankenstein* Web UI:
  
  ```
    dp_uart_data = 0x0036001c;
    dc_ptu_uart_lsr = 0x00360424;
  ```
    
* Create the `patch` directory and copy `CYW20735B1/patch/hello.c`.
* Run `make all -C projects/CYW20819A1/`
* ...it builds! Ship it! :D

Running patches on the evaluation board (`hello` patch)
-------------------------------------------------------
* It won't run though, memory addresses need to be fixed.
* In the *Frankenstein* Web UI, click on *Edit Config* and set `PATCH_CODE_BASE` to a reasonable value, i.e.,
  `0x20A000`. While the evaluation board does not have any memory protection and code can be written and executed
  anywhere in RAM, you still need to check that the memory is currently not in use.
  * To verify that the area is empty, perform `hd [address]`.
  * Also try to write and execute something with `writeasm [address] bx lr` and `launch [address]`. This should
    work without crashing.
  * You can get some hints from the SDK, in our case the variable is called `PLATFORM_DIRECT_LOAD_BASE_ADDR`
    and located in `ModusToolbox_1.1/libraries/bt_20819A1-1.0/components/BT-SDK/20819-A1_Bluetooth/platform.mk`.
* Run `make all -C projects/CYW20819A1/`
* Load the patch:
  * `sudo python2 internalBlueMod.py`
  * `loadelf projects/CYW20819A1/gen/hello.patch`
  
When everything works, the output should be:

```
[*] HCI device: hci0  [20:81:9A:09:3E:41]  flags=5<UP RUNNING>
[*] Connected to hci0
[*] Chip identifier: 0x220c (001.002.012)
[*] Using fw_0x220c.py
[*] Loaded firmware information for CYW20819.
[*] Try to enable debugging on H4 (warning if not supported)...
[!] _sendThreadFunc: Sending to socket failed, reestablishing connection.
    With HCI sockets, some HCI commands require root!
> loadelf projects/CYW20819A1/gen/hello.patch
[*] Loading .text @ 0x20a000 - 0x20a204 (516 bytes)
[*] Loading .rodata.str1.4 @ 0x20a204 - 0x20a23a (54 bytes)
[*] Loading .data @ 0x20a23c - 0x20a24d (17 bytes)
[*] Loaded 12836 symbols
 [?] Found nonzero entry point 0x20a1cd. Execute? [Yes/no]
[*] Firmware says: hello\o/
[*] Firmware says: from firmware
[*] Firmware says: _start = 0x20a1cd
```


`xmit_state` patch
------------------

Before being able to start emulation, we need to somehow be able to get a state from
that on we want to do our emulation and fuzzing.

Copy `patch/xmit_state.c` from the CYW20735B1 to the CYW20819A1 project.
Add missing *global* symbols to project via *Frankenstein* Web UI:


    patchram_address_table = 0x310000;
    patchram_enable = 0x310404;
    patchram_data_table = 0x270000;

The SDKs have a file called `patch.lst` that gives some hints about the locations. You can also check the
*InternalBlue* firmware definition files where to usually look for these.

Run `make all -C projects/CYW20819A1/`.

Now let's try to get a state. Something that is easy to trigger is device scanning. This is in `eir_handleRx`.

```
> xmitstate 0xA2624
[*] patchRom: Choosing next free slot: 0
[*] patchRom: Choosing next free slot: 35
projects/CYW20819A1/gen/xmit_state.patch
[*] Loading .text @ 0x20a000 - 0x20a608 (1544 bytes)
[*] Loading .rodata.str1.4 @ 0x20a608 - 0x20a64c (68 bytes)
[*] Loading .data @ 0x20a64c - 0x20a66d (33 bytes)
[*] Loading .bss @ 0x20a670 - 0x20ad00 (1680 bytes)
[*] Loaded 12859 symbols
[*] Firmware says: Hello \o/
[*] Firmware says: Hook Added
```

...and now trigger it by starting a scan using `hcitool scan`.

```
[*] Receiving firmware state: regs@0x20acf8 cont@0x20a044
[*] Received segment 0x0 - 0x200000
[*] Received segment 0x200000 - 0x250000
[*] Received segment 0x270000 - 0x280000
[!] Received Evaluation Stack-Dump Event (contains 10 registers):
[!] pc: 0x0020a20c   lr: 0x0020a4d3   sp: 0x00200208   r0: 0x00280000   r1: 0x00284000
    r2: 0x00280008   r3: 0x00200234   r4: 0x0007fdd4   r5: 0x002002b4   r6: 0x00280000
```

If you open Wireshark, you can see that there are many events coming in now, and the state dump takes a while.
Better do some cross-checking before you give up and think it got stuck. It most certainly didn't.

The reason for the stackdump here is that memory areas are defined differently on the newer evaluation board.
Thus, we also need to copy `map_memory.c` from the CYW20735B1 board to the CYW20819A1 board.
Run `make all -C projects/CYW20819A1/`.

```
> mapmemory 0x0
[*] Loading .text @ 0x20a000 - 0x20a31c (796 bytes)
[*] Loading .rodata @ 0x20a31c - 0x20a321 (5 bytes)
[*] Loading .rodata.str1.4 @ 0x20a324 - 0x20a33b (23 bytes)
[*] Loading .data @ 0x20a33c - 0x20a34d (17 bytes)
[*] Loading .bss @ 0x20a350 - 0x20a354 (4 bytes)
[*] Loaded 12847 symbols
[*] Firmware says: Hello \o/
Found Map 0x0 - 0x280000
Found Map 0x300000 - 0x308000
Found Map 0x310000 - 0x322000
Found Map 0x326000 - 0x330000
Found Map 0x338000 - 0x340000
Found Map 0x341000 - 0x342000
Found Map 0x350000 - 0x368000
Found Map 0x370000 - 0x380000
Found Map 0x390000 - 0x398000
Found Map 0x404000 - 0x408000
Found Map 0x410000 - 0x414000
Found Map 0x420000 - 0x424000
Found Map 0x430000 - 0x434000
Found Map 0x440000 - 0x444000
Found Map 0x450000 - 0x454000
Found Map 0x500000 - 0x541000
Found Map 0x580000 - 0x600800
Found Map 0x640000 - 0x640800
[!] Firmware died at address 0x650f00 while mapping memory
>  
```

Dying at `0x650f00` is kind of expected, that's coexistence registers and they might not be blocked for writing
despite not being properly initialized. We saw some other crashes related to the `0x650nnn` area.
Anyway, let's now go and put these into `xmit_state.c`. Afterwards, `xmitstate` will succeed:

``` 
...
[*] Received segment 0x650000 - 0x651000
[*] Received segment 0xe0000000 - 0xe0100000
[*] Received fuill firmware state
```


The latest `xmitstate` result will be displayed as active in the *Frankenstein* Web UI. Just navigate to
http://127.0.0.1:8000/project?projectName=CYW20819A1 and reload the page.
Now, rebuild the project:
      
      make all -C projects/CYW20819A1

If things break here, you might have screwed up with segment definitions, global vs. default scope, or similar.


`heap_sanitizer` patch
----------------------

Compiled after removing `memcpy_r`, so that one doesn't exist on the CYW20819A1.
If you have symbols, do a quick check that you didn't miss any `memcpy` instruction.
In our case, nothing was added.

```
~/Documents/ModusToolbox_1.1$ readelf -a -W libraries/bt_20819A1-1.0/components/BT-SDK/20819-A1_Bluetooth/WICED/internal/20819A1/patches/patch.elf | grep memcpy
   535: 00006d31     0 FUNC    GLOBAL DEFAULT  ABS memcpy
  1377: 0001845f     0 FUNC    GLOBAL DEFAULT  ABS sfi_memcpy
  3602: 000477d1     0 FUNC    GLOBAL HIDDEN   ABS __aeabi_memcpy4
  3603: 000477d1     0 FUNC    GLOBAL DEFAULT  ABS __aeabi_memcpy8
  3604: 000477d1     0 FUNC    GLOBAL DEFAULT  ABS __rt_memcpy_w
  3605: 00047819     0 FUNC    GLOBAL DEFAULT  ABS _memcpy_lastbytes_aligned
  4209: 00054687     0 FUNC    GLOBAL HIDDEN   ABS __aeabi_memcpy
  4210: 00054687     0 FUNC    GLOBAL DEFAULT  ABS __rt_memcpy
  4211: 000546ed     0 FUNC    GLOBAL DEFAULT  ABS _memcpy_lastbytes
  5733: 0007d747     0 FUNC    GLOBAL DEFAULT  ABS mpaf_memcpy
  6802: 00097ed5     0 FUNC    GLOBAL DEFAULT  ABS utils_memcpy8_postinc
  6803: 00097f21     0 FUNC    GLOBAL DEFAULT  ABS utils_memcpy8
  6804: 00097f59     0 FUNC    GLOBAL DEFAULT  ABS utils_memcpy3dword
  6807: 00097fa9     0 FUNC    GLOBAL DEFAULT  ABS utils_memcpy10
  8361: 000b67d1     0 FUNC    GLOBAL DEFAULT  ABS __ARM_common_memcpy4_5
  8516: 000ba075     0 FUNC    GLOBAL DEFAULT  ABS __ARM_common_memcpy4_10
```

...and then run it.

``` 
> loadelf projects/CYW20819A1/gen/heap_sanitizer.patch
```

__TODO:__
I think we need to call `_start` for the patch to become
effective, but this crashes. The patch can be loaded without crashing, but once the entry
point is executed, the firmware silently crashes.
...even when I remove everything from the `_start` function and double check that it is
just `bx lr`, before its execution everything is well and afterwards it gets non-responsive.

Minimal working example: even without patches, writing to the address `0x20a5dc` and executing it crashes.
Why is this even used?

`PLATFORM_DIRECT_LOAD_BASE_ADDR      := 0x20A000`

...so far so good.

`PLATFORM_APP_SPECIFIC_STATIC_LEN    ?= 1024`

Which adds up to `0x20a400`. So this patch might probably just exceed the maximum patch length on CYW20819A1.



Emulation
---------

Start with copying `emulation/execute.c` from the CYW20735B1.
Also copy `emulation/[bcs,common,dynamic_memory,fwdefs,hci,lm,queue,timer].h` and `emulation/bcs/[acl,inq,le,page].h`,
as these things are not yet moved cleanly into `/projects/common/`.

```
arm-none-eabi-ld: cannot find gen/internalBlue_11.07.2019_13.52.37/Segment_0x420000.segment.o
make: *** [Makefile:28: gen/execute.exe] Error 1
```

Happens due to executing as root to access hci0 on Linux, we need to change permissions on this file:
```
 './segment_groups/internalBlue_11.07.2019_13.52.37': Permission denied
```

Afterwards, the following registers are missing:

```
dc_nbtc_clk = 0x00318088;
dc_x_clk = 0x003186ac;
pcx_btclk = 0x0031822c;
pcx2_btclk = 0x0031823c;
pcx2_pbtclk = 0x00318238;
phy_status = 0x00314004;
pkt_hdr_status = 0x00318b28;
pkt_log = 0x00318b2c;
rtx_dma_ctl = 0x00314018;
rtx_mem_start1 = 0x00370400;
rtx_rx_buffer = 0x00370c00;
sr_status = 0x0031400c;
sr_ptu_status_adr4 = 0x00360084;
tx_pkt_info = 0x00318acc;
tx_pkt_pyld_hdr = 0x00318ad0;
```

Currently, various tasks and structures are hardcoded.
Locate and replace these.


Debugging notes
---------------

Just to show the workflow when something is not working :)
Basic ideas of how to analyze issues with IDA, gdb and the *InternalBlue* stackdumps etc.

---

With invalid `PLATFORM_DIRECT_LOAD_BASE_ADDR`:
```
> loadelf projects/CYW20819A1/gen/hello.patch
[*] Loading .text @ 0x230000 - 0x230204 (516 bytes)
[*] Loading .rodata.str1.4 @ 0x230204 - 0x23023a (54 bytes)
[*] Loading .data @ 0x23023c - 0x23024d (17 bytes)
[*] Loaded 12836 symbols
 [?] Found nonzero entry point 0x2301cd. Execute? [Yes/no]
[!] Received Evaluation Stack-Dump Event (contains 10 registers):
[!] pc: 0x00424000   lr: 0x0000f095   sp: 0x002209a8   r0: 0x002301ce   r1: 0x00000000
    r2: 0x00000000   r3: 0x00210438   r4: 0x002301cd   r5: 0x00220b20   r6: 0x00000001
```


* crashes in LR 0x0000f095 = btuarth4_HandleLaunch_RAM just at BLX R4
* PC 0x4240000 (not sure if valid?!), R4 is 0x002301cd

Corrected `PLATFORM_DIRECT_LOAD_BASE_ADDR`:
```
> loadelf projects/CYW20819A1/gen/hello.patch
[*] Loading .text @ 0x20a000 - 0x20a204 (516 bytes)
[*] Loading .rodata.str1.4 @ 0x20a204 - 0x20a23a (54 bytes)
[*] Loading .data @ 0x20a23c - 0x20a24d (17 bytes)
[*] Loaded 12836 symbols
 [?] Found nonzero entry point 0x20a1cd. Execute? [Yes/no]
[!] Received Evaluation Stack-Dump Event (contains 10 registers):
[!] pc: 0x0020a048   lr: 0x0020a1d5   sp: 0x00220990   r0: 0x000000fe   r1: 0x0020a210
    r2: 0x00000005   r3: 0x00000004   r4: 0x03541012   r5: 0x03538972   r6: 0x00000001
```

This happens in this code:
```
text:0020A030 hci_xmit_event                          ; CODE XREF: hci_puts+22↓j
.text:0020A030                                         ; hci_puts+28↓j ...
.text:0020A030
.text:0020A030 var_C           = -0xC
.text:0020A030 var_B           = -0xB
.text:0020A030 var_A           = -0xA
.text:0020A030
.text:0020A030                 PUSH    {R4,R5}
.text:0020A032                 LDR     R5, =0x3538972  ;                 "dp_uart_data": 55806322,
.text:0020A034                 LDR     R4, =0x3541012  ;                 "dc_ptu_uart_lsr": 55840786,
.text:0020A036                 SUB     SP, SP, #8
.text:0020A038                 MOVS    R3, #4
.text:0020A03A                 STRB.W  R0, [SP,#0x10+var_B]
.text:0020A03E                 STRB.W  R2, [SP,#0x10+var_A]
.text:0020A042                 STR     R3, [R5]
.text:0020A044                 STRB.W  R3, [SP,#0x10+var_C]
.text:0020A048
.text:0020A048 loc_20A048                              ; CODE XREF: hci_xmit_event+20↓j
.text:0020A048                 LDR     R3, [R4]        ; [!] pc: 0x0020a048   lr: 0x0020a1d5   sp: 0x00220990   r0: 0x000000fe   r1: 0x0020a210
.text:0020A048                                         ;     r2: 0x00000005   r3: 0x00000004   r4: 0x03541012   r5: 0x03538972   r6: 0x00000001
.text:0020A048                                         ;
.text:0020A048                                         ; -> crashes upon the first access to R4

```

Which is defined in `./projects/common/frankenstein/BCMBT/patching/hciio.h`.
The access to R4 crashes, which is `dc_ptu_uart_lsr`. So it was probably redefined
in the CYW20819A1?

We grep again for the register names in *WICED Studio*. They are defined as follows in all versions
of eval boards supported:

    #define dp_uart_data_adr      0x0036001c                   // ptu_adr_base + 0x0000001c
    #define dc_ptu_uart_lsr_adr   0x00360424                   // uart_base + 0x00000024

...so the values above were probably caused by a double hex conversion.

---

Some compiler stuff seems also to be weird.

```
/usr/include/bits/socket.h:354:11: fatal error: asm/socket.h: No such file or directory
 # include <asm/socket.h>
           ^~~~~~~~~~~~~~
```

Can be solved with:
``` 
cd /usr/include/
sudo ln -s asm-generic/ asm
```

---

I used default instead of global scope and then didn't know how to modify it except from writing
directly to `project.json`. So I just re-created the project. In that case, somehow the `segment_groups`
folder got lost, probably because I also didn't create the 0x0 segment it was never created by the scripts.
Fixed by adding a folder `projects/CYW20819A1/segment_groups/` by hand.

```
  ...
  File "/home/jiska/seemoo/research/bluetooth/frankenstein/core/project.py", line 254, in add_group
    os.mkdir(group_path)
OSError: [Errno 2] No such file or directory: 'projects/CYW20819A1/segment_groups/internalBlue_11.07.2019_13.42.01'
```

---

Without redefining all symbols and escaping some special situations, you might run into weird
crashes like this one:

``` 
$ qemu-arm projects/CYW20819A1/gen/execute.exe 
lr=0x20a68d eir_handleRx(0x20c668);
lr=0x07990b bcs_kernelBtProgIntEnable(0x02, 0x02, 0x02, 0x50);
lr=0x04b951 bcs_kernelSlotCbFunctions()lr=0x0bf003bd bcs_SlotCbFunctions()lr=0x01fba9 lm_sendInqFHS(0x202d04)lr=0x0bf01159 dynamic_memory_AllocatePrivate(0x200498, 0x0, 0x0);
qemu: uncaught target signal 4 (Illegal instruction) - core dumped
Illegal instruction
```

Debugging works as follows:
```qemu-arm -g 31337 projects/CYW20819A1/gen/execute.exe```

In a new window, start `gdb`. (Might require `gdb-multiarch` or `gdb-arm-none-eabi`.)

``` 
(gdb) target remote 127.0.0.1:31337
Remote debugging using 127.0.0.1:31337

### (... some IDA magic to find out where we are roughly crashing)

(gdb) break *0x1F66
Breakpoint 4 at 0x1f66
(gdb) continue
Continuing.

Breakpoint 4, 0x00001f66 in ?? ()
(gdb) stepi
0x0007ec9e in ?? ()
(gdb) info r
r0             0x200498 2098328
r1             0x21     33
r2             0x20     32
r3             0x3      3
r4             0x200498 2098328
r5             0x2106bc 2164412
r6             0x0      0
r7             0x200da8 2100648
r8             0x73c76  474230
r9             0x2      2
r10            0x7800   30720
r11            0x200de4 2100708
r12            0x18     24
sp             0x200350 0x200350
lr             0x1f6b   8043
pc             0x7ec9e  0x7ec9e
cpsr           0x20000030       536870960
(gdb) stepi

Program received signal SIGILL, Illegal instruction.
0x0007ec9e in ?? ()
(gdb) 
```

So this happened within the following function, that is called by `dynamic_memory_AllocateOrDie`:

``` 
code_rom:000A43EE             synch_GetXPSRExceptionNumber            ; CODE XREF: dynamic_memory_AllocateOrDie+26↑p
code_rom:000A43EE                                                     ; dynamic_memory_AllocateOrReturnNULL+26↑p ...
code_rom:000A43EE EF F3 03 80                 MRS.W   R0, XPSR
code_rom:000A43F2 4F EA 00 60                 MOV.W   R0, R0,LSL#24
code_rom:000A43F6 4F EA 10 60                 MOV.W   R0, R0,LSR#24
code_rom:000A43FA 70 47                       BX      LR
code_rom:000A43FA             ; End of function synch_GetXPSRExceptionNumber
```

This function can simply be disabled. It was already defined to be skipped but the address
of this function was hard coded in our case. Exceptions are located in `common.h` and disabled
via `patch_return(synch_GetXSPRExceptionNum)`.
Overall, most functions that do not work out to be emulated can just be disabled.


---

Missing `idle_loop` is also strange. 

```
qemu: unhandled CPU exception 0x9 - aborting
R00=10000000 R01=e000e000 R02=00000000 R03=00000000
R04=00000000 R05=00205888 R06=00200ba8 R07=00000000
R08=00000000 R09=00000000 R10=00225b44 R11=00000000
R12=00000000 R13=002003d8 R14=fffffffd R15=fffffffc
PSR=60000030 -ZC- T S usr32
```

Once you find it in `gdb`, the last steps are:

``` 
_tx_thread_context_restore: 0x00010574, 0x10596 -> here, LR is already set to 0xfffffffd (idle hook!)
(stepi 400 -> Cannot access memory at address 0xfffffffc)
(gdb) stepi
0x00010598 in ?? ()
(gdb) stepi
0x0001059a in ?? ()
(gdb) stepi
0x0001059e in ?? ()
(gdb) stepi
0x000105a2 in ?? ()
(gdb) stepi
0x000105a6 in ?? ()
(gdb) stepi
0xfffffffc in ?? ()
```