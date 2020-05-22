#include <frankenstein/utils.h>
#include "common.h"
#include "queue.h"
#include "lm.h"
#include "hci.h"

void hci_idle_loop() {
    while(1) {
        bcs_tick();
        contextswitch();
        check_and_handle_timers(1000);
        contextswitch();
        hci_rx_poll(1);
        contextswitch();
    }
}

void _start() {
    patch_code();
    idle_loop = hci_idle_loop;

    print("asd\n");
    hci_rx_fd = 0;
    hci_tx_fd = 1;
    print("asd\n");

    int rnd = open("/dev/urandom", O_RDONLY);
    acl_fd = rnd;
    inq_fd = rnd;
    page_fd = rnd;
    le_fd = rnd;

    //disconnect all connections
    //still do not know, why this crashes....
    print("asd\n");
    patch_jump(rm_getBBConnectedACLUsage, ret0);
    print("asd\n");

    //alarm(1);
    cont();
}
