#include <stdint.h>

extern int uart_DirectWrite(char *data, int len); //0x629a7 on CYW20735
extern volatile int dc_ptu_uart_lsr; //0x360424 on CYW20735
extern volatile int dp_uart_data;
//extern volatile int sr_ptu_status;

extern int uart_write(char *data, int len) {
    for (int i=0; i < len; i++) {
        dp_uart_data = data[i];
        //while (sr_ptu_status & 0x1);
        //sr_ptu_status = 1;

        //while ((dc_ptu_uart_lsr & 0xc) != 8); //Wait for data to be sent
        //while (dc_ptu_uart_lsr & 8); //Wait for data to be sent

        #ifdef HCI_DELAY
            for (volatile int t=0; t < HCI_DELAY; t++);
        #endif

    }

    /*
    do {
        sr_ptu_status = 0x2;
    } while (!(sr_ptu_status & 0x2));
    while((dc_ptu_uart_lsr & 0x10));
    */
}

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
    uart_write(hci_hdr, 3);
    while ((dc_ptu_uart_lsr & 0xc) != 8); //Wait for data to be sent
    uart_write(data, len);
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


/*
I/O macros used in the fw
*/
#ifndef FRANKENSTEIN_EMULATION
    #define print(s) hci_puts(s)
    char hex_chars[] = "0123456789abcdef";
    void print_ptr(uint32_t p) {
        char hex_str[] = "0x00000000";
        char not_skip_prefix = 0;
        char *c = hex_str+2;

        for (int i=sizeof(uint32_t)-1; i>=0; i--) {
            if (not_skip_prefix = not_skip_prefix | ((p>>(i*8)&0xff))) {
                *(c++) = hex_chars[(p>>(i*8+4))&0xf];
                *(c++) = hex_chars[(p>>(i*8))&0xf];
            }
        }
        if (!not_skip_prefix) *(c++) = '0';
        *(c++) = '\0';
        print(hex_str);
    }
    #define print_var(x) {print(#x" = "); print_ptr((uint32_t)x); print("\n");}
#endif



