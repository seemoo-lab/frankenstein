#include <frankenstein/utils.h>
#include <frankenstein/hook.h>
#include <frankenstein/xmit_state_emu.h>
#include "common.h"
#include "queue.h"


#include <sys/stat.h>
#include <fcntl.h>


void do_exit() {
   exit(0); 
}

void _start() {
    patch_code();
    char bd_addr[6];

    inqfilter_init();
    for (int i=0; i < 1024; i++) {
        *(int *)bd_addr = i;
        inqfilter_registerBdAddr(bd_addr, 0);
        print_var(i);
    }

    exit(0);
    
}
