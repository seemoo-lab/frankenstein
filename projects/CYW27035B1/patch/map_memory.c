#include <frankenstein/BCMBT/patching/patchram.h>
#include <frankenstein/BCMBT/patching/hciio.h>
#include <frankenstein/patching/map_memory.h>

void wiced_hal_wdog_restart();
void _start() {
    //launch ram complete
    hci_xmit_event(0x0e, "\x01\x4e\xfc\x00", 4);

    print("Hello \\o/\n");
    asm("CPSID I;"); //disable interrupts

    map_memory();
}
