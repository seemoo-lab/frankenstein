#include <frankenstein/BCMBT/patching/hciio.h>

int _start() {
    print("hello");
    print("\\o/\nfrom firmware\n");


    hci_xmit_event(0x0e, "\x01\x4e\xfc\x00", 4);
    while(1) {
        print("hello\n");
    }

    return 0;
}
