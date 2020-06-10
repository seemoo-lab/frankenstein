#include <frankenstein/utils.h>
#include "common.h"
#include "queue.h"
#include "lm.h"
#include "hci.h"

//#include <btattach.h>

//socat -d -d pty,raw,echo=1 exec:"stdbuf -o 0 -i 0 qemu-arm gen/hci_cmd.exe",pty,raw,echo=0

int coutdown = 1;
void hci_idle_loop() {
    while(1) {
        bcs_tick();
        contextswitch();
        check_and_handle_timers(1000);
        contextswitch();
        hci_rx_poll(1);
        contextswitch();

        if ((tb == &inqScanTaskStorage || tb == &pageScanTaskStorage) && !coutdown--) { //GoTo HCI Fuzz Mode
        //if (tb == 0x282250 && !coutdown--) { //GoTo HCI Fuzz Mode
            print("Enter HCI Redirect\n");
            char c = 0x42;
            write(1, &c, 1);//notify we are ready
            while(1) {
                struct pollfd ufds;
                char buff[1024];
                int n;


                ufds.fd = 0;
                ufds.events = POLLIN;
                if (poll(&ufds, 1, 1)) {
                    if ( (n = read(0, buff, 1024)) <= 0) exit(1);
                    write(hci_tx_fd, buff, n);
                }

                ufds.fd = hci_rx_fd;
                ufds.events = POLLIN;
                if (poll(&ufds, 1, 1)) {
                    if( (n = read(hci_rx_fd, buff, 1024)) <= 0) exit(1);
                    write(1, buff, n);
                }
            }
        }
    }
}



void _start() {
    patch_code();
    idle_loop = hci_idle_loop;

    acl_fd = -1;
    page_fd = -1;
    hci_attach();


    /*
    Ok, no idea, why reset is not working
    I will disable function by function to narrow it down
    */
    //patch_return(bt_Reset); //root of problem
    //patch_return(bcs_kernelBlock); //causes hardware error hci event

    //disconnect all
    patch_jump(rm_getBBConnectedACLUsage, ret0);

    /*
    taskActiveList = &taskActiveList;
    taskTimerList = &taskTimerList;
    _tx_event_flags_set(&taskEventGroup, 1, 0);
    */
    //bcs_kernelTimerTick();

    /*
    Endof of reset Debug
    */

    trace(bthci_event_AttemptToEnqueueEventToTransport,1,false);
    trace(bthci_processingHCIReset, 2, true);
    trace(bthci_lm_thread_Reset,2, true);
    trace(bcs_kernelBlock, 0, false);

    trace(bthci_acl_Reset,2 ,true);
    trace(bt_Reset, 0, false);

    cont();
}
