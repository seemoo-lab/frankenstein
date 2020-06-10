#include <frankenstein/utils.h>
#include "common.h"
#include "queue.h"


int n_steps = 128;
void acl_idle_loop() {
    while(1) {
        check_and_handle_timers(312);

        hci_rx_poll(1);
        hci_rx_poll(1);
        hci_rx_poll(1);
        contextswitch();

        if (!n_steps--) {print("Exit\n"); exit(1);}
        bcs_tick();
        contextswitch();
    }
}

void _start() {
    patch_code();
    idle_loop = acl_idle_loop;

    #ifdef DEBUG
        diag_sendLmpPktFlag = 0;
        hci_tx_fd = 1;
        hci_dump_raw_enable = 1;
    #else
        diag_sendLmpPktFlag = 0;
    #endif

    //int sockfd = tcp_connect(127,0,0,1,31337);
    int sockfd = -1;
    hci_tx_fd = sockfd;
    hci_rx_fd = sockfd;

    acl_fd = 0;

    //alarm(1);
    cont();
}
