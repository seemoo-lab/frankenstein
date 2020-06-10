#ifndef HCI_H
#define HCI_H

#include <frankenstein/BCMBT/hci.h>
#include "common.h"

extern uint32_t sr_ptu_status_adr4; //HCI UART status register

void interruptvector_PTU(); //Interrupt handler


//0x249f70 = g_uart_DriverState
//print_var(*(char*)(0x249e58+429)); //rx state

void *uart_ReceiveDMADoneInterrupt(uint32_t);



/*
If the firmware goes to an idle state, we execute the interrupt
and notify the firmware for new HCI data
*/
void hci_rx_poll(int timeout_ms) {
    if (hci_rx_fd == -1) return;
    struct pollfd ufds;
    int ret = 0;

    //setup poll for hci rx fd
    ufds.fd = hci_rx_fd;
    ufds.events = POLLIN;
    ret = poll(&ufds, 1, timeout_ms);

    //Test if there is actual data available
    int count;
    ioctl(hci_rx_fd, FIONREAD, &count);
    if (count == 0) return;

    //No Data Available
    if (ret <= 0) return;

    //classical receive
    sr_ptu_status_adr4 |= 0x04; //set register to data available
    interruptvector_PTU();

    //the UART interface seems to have a DMA like receive
    char state = *(char *)(0x249f70 + 0xd); //rx_machine state
    print_var(state);
    if (state == 6) {
        void *data_ptr = *(void **)(0x249f70 + 0x10); //rx_data_ptr
        uint32_t len = *(uint32_t *)(0x249f70 + 0x14); //rx_len
        int ret;
        print_var(data_ptr);
        print_var(len);
        print("\033[;32mRx DMA ");
        for (ret = -1; ret < 0; ret = read(hci_rx_fd, data_ptr, len));
        *(uint32_t*)(0x249f70 + 0x3c) = ret;
        hexdump(data_ptr, len);
        print("\033[;00m\n");
        print_var(*(uint32_t*)(0x249f70 + 0x3c));
        //interruptvector_DMA_DONE(); //XXX this is the actual interrupt handler called invoking uart_ReceiveDMADoneInterrupt
        uart_ReceiveDMADoneInterrupt(0x249f70); //Invoking isr directly
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
    patch_jump(uart_DirectWrite, &uart_DirectWrite_hook); //not required 
    patch_jump(uart_SendSynch, &uart_SendSynch_hook); //notr required
    //ret0 is needed to notify the state machine, that the data has been sent immediately
    add_hook(uart_SendAsynch, &uart_SendAsynch_hook, (uint32_t (*)(uint32_t, void *))ret0, NULL); //XXX Working

    jump_trace(uart_DirectRead, uart_DirectRead_hook, 2, false);

    //hci uart rx
    patch_jump(mpaf_hci_EventFilter, &ret0); //we dont want any hci events to be droped
    patch_jump(uart_SetAndCheckReceiveAFF, &ret0); //there is never data available on uart
    patch_jump(uart_ReceiveSynch, &uart_ReceiveSynch_hook);

    trace(uart_ReceiveAsynch, 3, true);
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
    trace(uart_ReceiveDMADoneInterrupt, 1, false);
}



#endif
