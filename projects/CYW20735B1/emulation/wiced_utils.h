#include "fwdefs.h"




/*
* XMIT Memory
*/

void xmit_int(int x){
    puart_write(x);
    puart_write(x>>8);
    puart_write(x>>16);
    puart_write(x>>24);
}

void xmit_segment(int addr, int len) {
    xmit_int(addr);
    xmit_int(len);
    for (; len; len -= 4, addr += 4)
        xmit_int(*(int*)addr);
}

#ifndef EMULATED
void puts(char *s) {for(;*s;s++) puart_write(*s);}

int cont;
void wiced_hal_wdog_disable();

#endif

#define sendlmp(conn, x) {char *buff; buff = lm_allocLmpBlock(); memcpy(buff+12,x,19); DHM_LMPTx(conn, buff);}
