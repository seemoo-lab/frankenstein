#ifndef HCI_H
#define HCI_H


#include <frankenstein/BCMBT/hci.h>
#include "common.h"


/*
Some debug stuff, deprecated
*/ /*
void dump_rx_state(){
    print_var(*(int*)(0x249e58+429));
    print_var(g_uart_DriverState);
    print_var(g_ptu_ISR);
    print_var(*(int*)(0x360084));
    print_var(*(int*)(0x3600a8));
    print_var(*(int*)(0x3600cc));
    print_var(*(int*)(0x3382d8));
    print_var(*(char*)(0x249f70+13));
    print_var(*(char*)(0x249f70+14));
    // *(int*)(0x360084) = 0x0a;
} */


/*
If the firmware goes to an idle state, we execute the interrupt
and notify the firmware for new HCI data
*/
void hci_rx_poll(int timeout_ms) {
    if (hci_rx_fd == -1) return;

    //setup poll for hci rx fd
    struct pollfd ufds;
    int ret = 0;
    ufds.fd = hci_rx_fd;
    ufds.events = POLLIN;
    ret = poll(&ufds, 1, timeout_ms);
    if (ret <= 0) return; //No Data Available

    int count;
    ioctl(hci_rx_fd, FIONREAD, &count);
    if (count == 0) return;

    //classical receive
    sr_ptu_status_adr4 |= 0x04; //set register to data available
    interruptvector_PTU();

    //the UART interface seems to have a DMA like receive
    // g_uart_DriverState points to 0x249F70 on CYW20735, but to 0x220B20 on CYW20819
    char state = *(char *)(&g_uart_DriverState + 0xd); //rx_machine state //TODO remove todo once we know that this is the correct reference
    print_var(state);
    if (state == 6) {
        void *data_ptr = *(void **)(&g_uart_DriverState + 0x10); //rx_data_ptr //TODO
        uint32_t len = *(uint32_t *)(&g_uart_DriverState + 0x14); //rx_len //TODO
        int ret;
        print_var(data_ptr);
        print_var(len);
        print("\033[;32mRx DMA ");
        for (ret = -1; ret < 0; ret = read(hci_rx_fd, data_ptr, len));
        *(uint32_t*)(&g_uart_DriverState + 0x3c) = ret; //TODO
        hexdump(data_ptr, len);
        print("\033[;00m\n");
        print_var(*(uint32_t*)(&g_uart_DriverState + 0x3c)); //TODO
        //interruptvector_DMA_DONE(); //XXX this is the actual interrupt handler called invoking uart_ReceiveDMADoneInterrupt
        uart_ReceiveDMADoneInterrupt(&g_uart_DriverState); //Invoking isr directly //TODO
    }

}

void hci_attach() {
    //open ptmx
    int ptmx = ptmx_open();
    char *pts_name = ptmx_name(ptmx);
    print("Pts:");
    puts(pts_name);
    print("\n");
    ptmx_btattach(ptmx);

    hci_tx_fd = ptmx;
    hci_rx_fd = ptmx;

    //wait for Data
    struct pollfd ufds;
    ufds.fd = ptmx;
    ufds.events = POLLIN;
    while (poll(&ufds, 1, 100) <= 0);

}



void hci_install_hooks() {
    //trace uart
    trace(btuartcommon_SendHCICommandBackToTransportThread, 2, true);

    //hci uart tx
    patch_jump(&uart_DirectWrite, &uart_DirectWrite_hook); //not required 
    patch_jump(&uart_SendSynch, &uart_SendSynch_hook); //notr required
    //ret0 is needed to notify the state machine, that the data has been sent immediately
    add_hook(uart_SendAsynch, &uart_SendAsynch_hook, ret0, NULL); //XXX Working

    //hci uart rx
    patch_jump(&mpaf_hci_EventFilter, &ret0); //we dont want any hci events to be droped
    patch_jump(&uart_SetAndCheckReceiveAFF, &ret0); //there is never data available on uart
    patch_jump(&uart_DirectRead, &uart_DirectRead_hook);
    patch_jump(&uart_ReceiveSynch, &uart_ReceiveSynch_hook);

    trace(uart_ReceiveAsynch, 3, true);
    trace(uart_DirectRead, 3, true);
    trace(uart_SendSynchHeaderBeforeAsynch, 4, false);
    trace(uart_SendAsynch, 4, true);
    trace(uart_SendSynch, 4, false);
    trace(uart_DirectWrite, 2, true);


    trace(btuarth4_RunTxStateMachines, 4, true);
    trace(bttransport_SendMsgToThread,2,false);
    trace(btu_hcif_hardware_error_evt,2,false);
    trace(mpaf_thread_PostMsgToHandler, 1, false);
    trace(bthci_lm_thread_SendMessageToThread, 1, false);
    trace(uart_SetupForRXDMA, 1, false);
}



#endif
