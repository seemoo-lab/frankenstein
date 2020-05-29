#ifndef __FRANKENSTEIN_BCMBT_HCI_H
#define __FRANKENSTEIN_BCMBT_HCI_H


int hci_tx_fd = -1;
int hci_rx_fd = -1;
int hci_dump_raw_enable = 0; //we wait until the first hci cmd before dumping events

/*
Sending hci Events
*/

void uart_SendSynch(void *uart_struct, char *data, int len);
void uart_SendSynch_hook(void *some_struct, char *data, int len) {
    print("\033[;32mHCI Event (Synch)");
    hexdump(data,len);
    print("\033[;00m");

    return; //XXX called in send header before ...
    if (hci_tx_fd != -1 && hci_dump_raw_enable) {
        write(hci_tx_fd, (void *)data, len);
    }
}

void uart_SendAsynch(void *uart_struct, char *data, int len, int x);
void uart_SendAsynch_hook(struct saved_regs *regs, void *arg) {
    uint32_t size = *(uint32_t*) regs->sp;
    print("\033[;32mHCI Event (Asynch)");
    hexdump(regs->r1, regs->r2); //header aka type
    hexdump(regs->r3, size); //hci packet
    print("\033[;00m\n");

    //dump raw packets
    if (hci_tx_fd != -1 && hci_dump_raw_enable) {
        write(hci_tx_fd, (void*) regs->r1, regs->r2);
        write(hci_tx_fd, (void*) regs->r3, size);
    }
}

void *uart_DirectWrite(char *data, int len);
void uart_DirectWrite_hook(char *data, int len) {
    print("\033[;32mHCI Event (Direct Write)");
    hexdump(data, len);
    print("\033[;00m\n");

    return;
    if (hci_tx_fd != -1 && hci_dump_raw_enable) {
        write(hci_tx_fd, (void *)data, len);
    }
}

/*
Reading HCI packets
*/

/*
This is called in the interrupt handler to complete a Asynch read
*/

int uart_DirectRead_hook(char *data, int len) {
    int ret;
    print("\033[;32mHCI Direct Read ");
    for (ret = -1; ret < 0; ret = read(hci_rx_fd, data, len));
    hexdump(data, len);
    print("\033[;00m\n");

    hci_dump_raw_enable = 1;
    if (ret == 0) exit(1); //no more to read, exit
    return ret;
}

/*
This method tries to receive directly from the uart and loops forever, as there are no data to read
Therefore, wee hook it
*/
int uart_ReceiveSynch_hook(void *uart_struct, char *data, int len) {
    print("\033[;32mHCI ReceiveSynch ");
    int ret;
    for (ret = -1; ret < 0; ret = read(hci_rx_fd, data, len));
    hexdump(data, len);
    print("\033[;00m\n");

    hci_dump_raw_enable = 1;
    return 8;
}

#endif
