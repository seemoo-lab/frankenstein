#include <frankenstein/BCMBT/patching/hciio.h>

int bthci_event_SendCommandCompleteEventWithStatus(int hci_event, char status);


// TODO see Nexus 5 randp.py and try with assembly first
/*
    push lr
    mov  r0, #0xFC4E // launch RAM command
    mov  r1, 0       // event success
    bl   0xC9A1C      // bthci_event_SendCommandCompleteEventWithStatus
    // implement any code here
    pop pc
*/

// TODO launch_ram is disabled b/c there's a global thread variable set
// g_bttransport + 52 (here 0x2883f8) should be pointing to btuartcommon_SendHCICommandBackToTransportThread+1 (here 0xCB8F5)

// TODO nope this doesn't fix launch_ram :(
int fix_launchram() {
    bthci_event_SendCommandCompleteEventWithStatus(0xfc4e, 0); // launch_ram with status success
    for (int i=0; i<0x4000; ++i);   // wait (similar to nexus 5 implementation)
}

int _start() {
    fix_launchram();    // specific to the iphone
    print("hello");
    print("\\o/\nfrom firmware\n");
    print_var(_start);
    return 0;
}
