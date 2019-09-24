#include <stdint.h>

extern int uart_DirectWrite(char *data, int len); //0x629a7 on CYW20735
extern volatile int dc_ptu_uart_lsr; //0x360424 on CYW20735

/*
We are using uart_DirectWrite to generate HCI events
This function does not rely on the bttransport state machine
and makes direct use of the UART hw regs
*/
void hci_xmit_event(char event_code, char *data, char len) {
    char hci_hdr[3];
    hci_hdr[0] = 0x04; //HCI Event
    hci_hdr[1] = event_code;
    hci_hdr[2] = len;
    uart_DirectWrite(hci_hdr, 3);
    uart_DirectWrite(data, len);

    while ((dc_ptu_uart_lsr & 0xc) != 8); //Wait for data to be sent
}

/*
Print debug messages in internalBlue
*/
void hci_puts(char *s) {
    int len;
    for (len=0; s[len] && len < 0xff; len++);
    hci_xmit_event(0xfe, s, len);
}

/*
Print hex data in internalBlue
*/
void hci_xmit_hex(char *data, char len) {
    hci_xmit_event(0xfd, data, len);
}


/*
Notify host for incomming state
*/
void hci_xmit_state_notify(void *regs, int cont) {
    uint32_t report[2];
    report[0] = (uint32_t)regs;
    report[1] = (uint32_t)cont;
    hci_xmit_event(0xfc, (char *)&report, sizeof(report));
}

/*
Send memory segment to host
*/
void hci_xmit_segment(int start, int stop) {
    uint32_t buff[32+3];
    buff[0] = start;
    buff[1] = stop-start;
    for (uint32_t current=start; current < stop; current += 128) {
        buff[2] = current;
        for (int i=0; i < 32; i++) buff[3+i] = ((uint32_t*)current)[i];
        hci_xmit_event(0xfb, (char *)buff, 128+12);
    }
}

/*
Used by map_memory to report mapped segments
*/
void hci_xmit_map_report(uint32_t ptr) {
    hci_xmit_event(0xfa, (char *)&ptr, 4);
}

#ifndef FRANKENSTEIN_EMULATION
    #define print(s) hci_puts(s)
#endif



