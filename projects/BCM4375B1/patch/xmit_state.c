#include <frankenstein/BCMBT/patching/patchram.h>
#include <frankenstein/BCMBT/patching/hciio.h>
#include <frankenstein/patching/xmit_state.h>


//void wiced_hal_wdog_disable();
struct hook *xmit_hook;
int rand();

void xmit_memory(struct saved_regs *regs, int cont) {
    //Ensure nothing interrupts us
    //wiced_hal_wdog_disable();
    asm("CPSID I;"); //disable interrupts

    //Overwriting hook code with 'ldr pc,[pc,#24]
    //This will skip the post_hook handler and prevents the hook
    //from beeing re-installed
    //It is also required to 
    //*(uint32_t*)xmit_hook = 0xf018f8df;

    //Notify the host, that a firmware start is comming
    //Also export the entry point that way
    hci_xmit_state_notify(regs, cont);

    //hci_xmit_segment(0x0,        0x140000);
    hci_xmit_segment(0x0,      0x140000);
    hci_xmit_segment(0x160000, 0x180000);
    hci_xmit_segment(0x200000, 0x288100);
    hci_xmit_segment(0x300000, 0x308000);
    hci_xmit_segment(0x310000, 0x322000);
    hci_xmit_segment(0x324000, 0x368000);
    hci_xmit_segment(0x370000, 0x380000);
    hci_xmit_segment(0x390000, 0x398000);
    hci_xmit_segment(0x500000, 0x601000);
    hci_xmit_segment(0x604800, 0x605000);
    hci_xmit_segment(0x640000, 0x641000);
    hci_xmit_segment(0x650000, 0x650600);
    hci_xmit_segment(0x650c00, 0x650f00);
    hci_xmit_segment(0x651000, 0x651800);
    hci_xmit_segment(0x652000, 0x652600);
    hci_xmit_segment(0x652c00, 0x652f00);
    hci_xmit_segment(0x653000, 0x653800);
    hci_xmit_segment(0x654000, 0x654400);
    hci_xmit_segment(0x680000, 0x8e5b00);
    hci_xmit_segment(0x8f3600, 0x8f5b00);
    hci_xmit_segment(0x96b000, 0x96d500);
    hci_xmit_segment(0x9e1800, 0x9e2300);

    //Notify Done
    hci_xmit_state_notify(0, 0);
}

void *xmit_state_target = NULL;

void _start() {
    print("Hello \\o/\n");
    hci_xmit_event(0x0e, "\x01\x4e\xfc\x00", 4);
    xmit_state();
    return;

    if (xmit_state_target) {
        xmit_hook = add_hook(xmit_state_target, xmit_state, NULL, NULL);
        print("Hook Added\n");
    } else
        print("Target is NULL\n");
}
