#include <frankenstein/utils.h>
#include <frankenstein/hook.h>
#include <frankenstein/xmit_state_emu.h>
#include "common.h"
#include "queue.h"

void inqfilter_init();
void inqfilter_registerBdAddr(char bdaddr[6], int);


void _start() {
    patch_code();
    char bd_addr[6] = {0x41, 0x41, 0x41, 0x41, 0x41, 0x41};

    inqfilter_init();
    for (unsigned char i=0; i < 0xff; i++) {
        bd_addr[0] = i;
        inqfilter_registerBdAddr(bd_addr, 0);
        print_var(i);
    }

    exit(0);
}
