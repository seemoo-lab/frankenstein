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
    hci_xmit_segment(0x0       , 0x00200000);   //Rom
    hci_xmit_segment(0x00200000, 0x00250000);   //MemCm3 volatile
    hci_xmit_segment(0x00270000, 0x00280000);   //MemPrc
    hci_xmit_segment(0x00280000, 0x00284000);   //Ram volatile
    hci_xmit_segment(0x00300000, 0x00308000);   //base_hw_regs_cm3_adr
    hci_xmit_segment(0x00310000, 0x00322000);
    hci_xmit_segment(0x00326000, 0x00330000);
    hci_xmit_segment(0x00338000, 0x00368000);
    hci_xmit_segment(0x00370000, 0x00380000);   //base_rtx_fifo_adr
    hci_xmit_segment(0x00390000, 0x00398000);   //base_power_WD_adr
    hci_xmit_segment(0x00410000, 0x00414000);   //base_bt_modem_regs_adr
    hci_xmit_segment(0x00420000, 0x00424000);   //base_fm_modem_regs_adr
    hci_xmit_segment(0x00430000, 0x00434000);   //base_mac154_top_adr
    hci_xmit_segment(0x00440000, 0x00444000);   //base_seceng_top_adr
    hci_xmit_segment(0x00450000, 0x00454000);   //base_capscan_top_adr
    hci_xmit_segment(0x00500000, 0x00600800);   //??? + rf_regs
    hci_xmit_segment(0x00640000, 0x00640800);   //base_clb_regs XXX not in memory map
    hci_xmit_segment(0x00650000, 0x00651000);   //gci_regs_adr_base XXX not in memory map

    //Those segments seem not to be relevant
    //hci_xmit_segment(0x20000000, 0x20250000);
    //hci_xmit_segment(0x20270000, 0x20284000);
    //hci_xmit_segment(0x20500000, 0x20600000);
    //hci_xmit_segment(0x22000000, 0x24000000);
    //hci_xmit_segment(0x40000000, 0x40004000);     //base_ToRam_alias_adr
    //hci_xmit_segment(0x42000000, 0x42080000);    //base_ToRam_bit_band_adr

    hci_xmit_segment(0xe0000000, 0xe0100000);    //ppb

    //Notify Done
    hci_xmit_state_notify(0, 0);
}

void *xmit_state_target = NULL;

void _start() {
    print("Hello \\o/\n");

    if (xmit_state_target) {
        xmit_hook = __add_hook(xmit_state_target, xmit_state, NULL, NULL);
        print("Hook Added\n");
    } else
        print("Target is NULL\n");
}
