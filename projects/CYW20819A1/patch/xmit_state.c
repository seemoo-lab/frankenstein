#include <frankenstein/BCMBT/patching/patchram.h>
#include <frankenstein/BCMBT/patching/hciio.h>
#include <frankenstein/patching/xmit_state.h>


void wiced_hal_wdog_disable();
struct hook *xmit_hook;

void xmit_memory(struct saved_regs *regs, int cont) {
    //Ensure nothing interrupts us
    wiced_hal_wdog_disable();
    asm("CPSID I;"); //disable interrupts

    //Overwriting hook code with 'ldr pc,[pc,#24]
    //This will skip the post_hook handler and prevents the hook
    //from beeing re-installed
    //It is also required to 
    *(uint32_t*)xmit_hook = 0xf018f8df;

    //Notify the host, that a firmware start is comming
    //Also export the entry point that way
    hci_xmit_state_notify(regs, cont);

    //Send the memory maps to host
    hci_xmit_segment(0x0       , 0x00280000);   //Rom, MemCm3 volatile, MemPrc
    hci_xmit_segment(0x00300000, 0x00308000);   //base_hw_regs_cm3 (dma, etc.)
    hci_xmit_segment(0x00310000, 0x00322000);   //prc_brk
    hci_xmit_segment(0x00326000, 0x00330000);   //??
    hci_xmit_segment(0x00338000, 0x00340000);   //mia (whatever this is, got imported from /projects/BCM20739_A0_ext1/
                                                //  users/yunlu/bcm20739a0/v_2015_0123_fpga/dip/mia/ver/param/mia_adrmap.h+mia_adr_base)
    hci_xmit_segment(0x00341000, 0x00342000);
    hci_xmit_segment(0x00350000, 0x00368000);
    hci_xmit_segment(0x00370000, 0x00380000);   //base_rtx_fifo_adr
    hci_xmit_segment(0x00390000, 0x00398000);   //base_power_WD_adr
    hci_xmit_segment(0x00404000, 0x00408000);   //base_ef_regs
    hci_xmit_segment(0x00410000, 0x00414000);   //base_bt_modem_regs_adr
    hci_xmit_segment(0x00420000, 0x00424000);   //base_fm_modem_regs_adr
    hci_xmit_segment(0x00430000, 0x00434000);   //base_mac154_top_adr
    hci_xmit_segment(0x00440000, 0x00444000);   //base_seceng_top_adr
    hci_xmit_segment(0x00450000, 0x00454000);   //base_capscan_top_adr
    hci_xmit_segment(0x00500000, 0x00541000);   //base_epm_ram
    hci_xmit_segment(0x00580000, 0x00600800);
    hci_xmit_segment(0x00640000, 0x00640800);   //base_clb_regs XXX not in memory map
    hci_xmit_segment(0x00650000, 0x00651000);   //gci_regs_adr_base XXX not in memory map

    /* On CYW20819A1 via map_memory.c:
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
        (died at 0x650f00, 0x67ff00)
        Found Map 0x20000000 - 0x2004a400
        Found Map 0x2004aa00 - 0x20280000
        Found Map 0x20500000 - 0x20541000
        Found Map 0x20580000 - 0x20600000
        Found Map 0x22000000 - 0x229b2100
        Found Map 0x229b2400 - 0x229b3c00
        Found Map 0x229b3e00 - 0x231b6e00
        Found Map 0x231b7600 - 0x231b7c00
        Found Map 0x231b9000 - 0x231b9900
        Found Map 0x231bab00 - 0x236c5b00
        Found Map 0x236c7e00 - 0x236c7f00
        Found Map 0x236c9800 - 0x236c9b00
        Found Map 0x236cb200 - 0x236cb500
        Found Map 0x236db700 - 0x236dc200
        Found Map 0x236e0500 - 0x236e0600
        Found Map 0x236e5400 - 0x236e5500
        Found Map 0x236e6e00 - 0x236e7000
        Found Map 0x236e8800 - 0x236e9b00
        Found Map 0x236ea200 - 0x238e1300
        Found Map 0x238ef100 - 0x238ef300
        Found Map 0x238f0b00 - 0x238f1700
        Found Map 0x238f2500 - 0x238f2700
        Found Map 0x2390ad00 - 0x2390af00
        Found Map 0x2390c700 - 0x2390d300
        Found Map 0x2390e100 - 0x2390e800
        Found Map 0x2390fb00 - 0x23910000
        Found Map 0x23911500 - 0x23911c00
        Found Map 0x23912f00 - 0x23914700
        Found Map 0x23914900 - 0x23b48900
        Found Map 0x23b4dc00 - 0x23b4dd00
        Found Map 0x23b69700 - 0x23b6a000
        Found Map 0x23b6b100 - 0x23b6c700
        Found Map 0x23b6cc00 - 0x23b6e400
        Found Map 0x23b6e600 - 0x23b6fc00
        Found Map 0x23b70000 - 0x23b70c00
        Found Map 0x23b74e00 - 0x23b74f00
        Found Map 0x23b76800 - 0x23b77e00
        Found Map 0x23b78200 - 0x23d9f500
        Found Map 0x23da9200 - 0x23daa100
        Found Map 0x23daac00 - 0x23daae00
        Found Map 0x23dbff00 - 0x23dc0200
        Found Map 0x23dc1900 - 0x23dc2000
        Found Map 0x23dc3400 - 0x23dc4a00
        Found Map 0x23dc4e00 - 0x23dc5700
    */

    hci_xmit_segment(0xe0000000, 0xe0100000);    //ppb

    //Notify Done
    hci_xmit_state_notify(0, 0);
}

void *xmit_state_target = NULL;

void _start() {
    print("Hello \\o/\n");

    if (xmit_state_target) {
        xmit_hook = add_hook(xmit_state_target, xmit_state, NULL, NULL);
        print("Hook Added\n");
    } else
        print("Target is NULL\n");
}
