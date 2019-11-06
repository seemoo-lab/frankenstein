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
  * Load *Symbols* and *Segments* to *default*.
     * For me, adding Segments were wrong! The Segments in the `patch.elf` were not useful. 
       Better create a large dummy segment.
     * ... but importing Symbols only worked. 
* Symbols for global variables are not included in `patch.elf`. In *WICED Studio*, they are contained in 
  the files `20719mapb0.h`, `20739mapb0.h` and `20703mapa0.h`. We do not have them in *Modus Toolbox*, but most
  of them stay the same over a long time. So we can carefully copy those variables that we need in the next step for
  compilation.
  Add the following variables via the *Frankenstein* Web UI:
    * `dp_uart_data` at 0x0036001c
    * `dc_ptu_uart_lsr` at 	0x00360424
* Create the `patch` directory and copy `CYW20735B1/patch/hello.c`.
* Run `make all -C projects/CYW20819A1/`
* ...it builds! Ship it! :D

Running patches on the evaluation board
---------------------------------------
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


xmit_state patch
---------------

Before being able to start emulation, we need to somehow be able to get a state from
that on we want to do our emulation and fuzzing.

Copy `patch/xmit_state.c` from the CYW20735B1 to the CYW20819A1 project.
Add missing symbols to project via *Frankenstein* Web UI:


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
Anyway, let's now go and put these into `xmit_state.c`.




Emulation
---------
* Add a binary to the project that you dumped with *InternalBlue* `dumpmem` previously.  
    * `sudo python2 internalBlueMod.py`
    * `dumpmem --file cyw20819a1.bin`
    * If you are going for a completely new chip, you might need to change the memory definitions in
      `internalblue/fw/fw_0x...py`.
      



Debugging notes
---------------

Just to show the workflow when something is not working :)

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


- crashes in LR 0x0000f095 = btuarth4_HandleLaunch_RAM just at BLX R4
- PC 0x4240000 (not sure if valid?!), R4 is 0x002301cd

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