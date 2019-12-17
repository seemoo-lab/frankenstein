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


void GKI_enqueue();
void GKI_os_malloc();
void _start() {
    patch_code();
    idle_loop = hci_idle_loop;

    hci_attach();
    diag_sendLmpPktFlag = 0;

    trace(GKI_enqueue, 4, true);
    trace(GKI_os_malloc, 4, true);


    trace(btuarth4_RunRxStateMachines,1,true);
    trace(uart_ReceiveSynch, 4, true);
    trace(uart_DirectRead, 4, true);
    trace(uart_ReceiveAsynch, 4, true);
    trace(uart_ReceiveAsynchTerminate, 4, true);
    trace(mpaf_hci_EventFilter,4, true);
    trace(uart_RunReceiveStateMachine,4, true);
    trace(dma_StartTransfer,3,true);
    trace(uart_SetupForRXDMA, 4, true);
    trace(bthci_event_AttemptToEnqueueEventToTransport,1,false);
    trace(bthci_processingHCIReset, 2, true);
    trace(bthci_lm_thread_Reset,2, true);
    trace(bcs_kernelBlock, 0, false);
    trace(bthci_acl_Reset,2 ,true);
    trace(bt_Reset, 0, false);


    //disconnect all connections
    //still do not know, why this crashes....
    patch_jump(rm_getBBConnectedACLUsage, ret0);

    cont();
}
