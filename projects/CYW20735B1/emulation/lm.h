#include <frankenstein/hook.h>

#ifndef __LM_H
#define __LM_H

void lm_LmpBBAcked(void *);                             //called if sent packet is acked
int DHM_isTxLmpListEmpty(void *adhm_acl);               //Returns true if there are no LMP packets left in LMP Tx lise
void *DHM_getFrontTxLmp(void *adhm_acl);                //Get first LMP packet in Tx list
void *rm_getConnFromBdAddress(char *);                  //Gets connection handle for BD address
void lm_LmpReceived(void *acl_conn, void *lmp_msg);     //Called for every received LMP packet in LM thread


struct lm_cmd {
    short type;
    short maybe_subtype;
    void *arg;
};

struct lcp_pckt {
    uint32_t unknwn0; //0x00
    uint32_t unknwn1; //0x4
    uint32_t unknwn2; //0x8
    unsigned char len;  //0xd
    unsigned char unknwn3;  //0xc
    uint16_t unknwn4; //0xe
    char data[];
};

void lm_hook(struct saved_regs *regs, void *arg) {
    struct lm_cmd *lm_cmd = (void *)regs->r0;
    struct lcp_pckt *lcp;

    //rssi report
    if (lm_cmd->type == 0xc) return;

    //inthexdump(regs->r0, 8);
    print("lr = ");
    print_ptr(regs->lr);
    print(" lm_sendCmd(");
    print_ptr(lm_cmd->type);
    print(" | ");
    print_ptr(lm_cmd->maybe_subtype);
    print(" | ");
    print_ptr(lm_cmd->arg);
    print(");\n");

    //lmulp_handleRxLcp
    if (lm_cmd->type == 0xe) {
        lcp = lm_cmd->arg;
        print("LCP: ");
        hexdump(lm_cmd->arg, 16); //hdr
        hexdump(lcp->data, lcp->len);
    }
}


void lmp_rx_hook(struct saved_regs *regs, void *arg) {
    print("lr = ");
    print_ptr(regs->lr);
    print(" lm_LmpReceived(");
    print_ptr(regs->r0);
    print(", ");
    hexdump(regs->r1, 4);
    print(" | ");
    hexdump(regs->r1 + 4, 24);
    print(");\n");
}

void lmp_tx_hook(struct saved_regs *regs, void *arg) {
    print("lr = ");
    print_ptr(regs->lr);
    print(" DHM_LMPTx(");
    print_ptr(regs->r0);
    print(", ");
    hexdump(regs->r1, 12);
    print(" | ");
    hexdump(regs->r1 +12, 19);
    print(");\n");
}




void add_lm_hooks() {
    add_hook(lm_sendCmd, lm_hook, NULL, NULL);
    add_hook(lm_LmpReceived, lmp_rx_hook, NULL, NULL);
    add_hook(DHM_LMPTx, lmp_tx_hook, NULL, NULL);

    trace(lm_LmpBBAcked, 2, false);
    trace(lm_HandleLmpBBAck, 2, false);
    trace(lm_sendCmdWithId, 1, false);
    trace(lm_LmpReceived, 2 ,false);
    trace(lm_HandleLmpReceivedPdu, 1, false);
    trace(rm_allocateACLConnPtr, 1, true);
    trace(rm_allocateLTCH, 1, true);
    trace(DHM_LMPTx, 2, false);
    trace(DHM_GetBasebandTxData, 2, true);
    trace(DHM_BasebandRx, 3, true);
    trace(lc_pageStart, 1, false);

}

#endif
