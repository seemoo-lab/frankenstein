#include <frankenstein/BCMBT/patching/hciio.h>
#include <frankenstein/BCMBT/patching/patchram.h>
#include <frankenstein/BCMBT/dynamic_memory.h>

//WriteRAM function
void *bt_boot_hci_WriteBytesToNonByteAddressableMemory(void *src, int len, void *dest);


int _start() {
    dynamic_memory_check_free_list("Load");
}
