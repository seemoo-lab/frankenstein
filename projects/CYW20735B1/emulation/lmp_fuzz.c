#include <frankenstein/utils.h>
#include <frankenstein/xmit_state_emu.h>
#include "common.h"
#include "queue.h"


char bd_addr[] = "\xbf\x56\x84\xc7\x95\xf8";
void lmp_idle_loop() {
    void *acl_conn;
    char lmp_msg[24];

    //xmit_state_emu("gen/xmited_lmp");

    while(1) {
        //from dhmAclAckRcvd
        while (!DHM_isTxLmpListEmpty(0x2811ec)) {
            void *buff = DHM_getFrontTxLmp(0x2811ec);
            if (buff) {
                lm_LmpBBAcked(buff);
                if (_tx_thread_execute_ptr != &g_pmu_idle_IdleThread) {
                    print("\033[;31mLmp Tx Ack, thread changed\033[;00m\n");
                    contextswitch();
                }
            } else break;
        }

        hci_rx_poll(100);
        hci_rx_poll(100);
        hci_rx_poll(100);
        contextswitch();

        //acl_conn = rm_getConnFromBdAddress(bd_addr);
        acl_conn = rm_getConnFromBdAddress("\xbf\x56\x84\xc7\x95\xf8");
        print_var(acl_conn);
        if (!acl_conn) exit(1);

        check_and_handle_timers(100);
        if (_tx_thread_execute_ptr != &g_pmu_idle_IdleThread) {
            print("\033[;31mLmp Rx, thread changed\033[;00m\n");
            contextswitch();
        }

        memset(lmp_msg, 0x00, 24);
        if (read(0, lmp_msg+4, 19) == 0)
            exit(1);

        //print("injected lmp "); hexdump(lmp_msg+4, 19);
        lm_LmpReceived(acl_conn, lmp_msg);
        contextswitch();

    }
}


#include <sys/stat.h>
#include <fcntl.h>
void _start() {
    patch_code();
    idle_loop = lmp_idle_loop;
    diag_sendLmpPktFlag = 0;
    
    //int sockfd = tcp_connect(127,0,0,1,31337);
    int sockfd = -1;
    hci_tx_fd = sockfd;
    hci_rx_fd = sockfd;

    alarm(1);
    cont();
}
