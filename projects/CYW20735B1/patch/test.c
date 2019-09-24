#include <frankenstein/BCMBT/patching/patchram.h>
#include <frankenstein/BCMBT/patching/hciio.h>
//#include <frankenstein/hook.h>

extern int patchram_data_table[];


void send_launch_ram_complete() {
}

void wiced_hal_wdog_disable();
int _start() {
    print("hello");
    print("\\o/\nfrom firmware\n");
    //write_code(0x190000,global);
    //*((int *)0x00) = 0xdeadbeef;
    //patchram_data_table[1] = 0;
    //asm("eor r0,r0;  CPSIE I; msr PRIMASK, r0;");

    //launch ram complete
    hci_xmit_event(0x0e, "\x01\x4e\xfc\x00", 4);

    asm("CPSID I;");
    wiced_hal_wdog_disable();
    //*((int*)0x329000) = 0x1f400;
    while (1) {
        int wdogv = *((int*)0x329000);
        hci_xmit_hex((char*)&wdogv, 4);
    }
    return 0;
}
