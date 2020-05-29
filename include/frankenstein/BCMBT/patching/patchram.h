#include <stdint.h>

#ifndef FRANKENSTEIN_EMULATION
/*
Patchram implementation running on the device
*/

#define PATCHRAM_SLOTS 255
extern int patchram_enable[];           // 0x310404 on CYW20735
extern int patchram_address_table[];    // 0x310000 on CYW20735
extern int patchram_data_table[];       // 0x270000 on CYW20735


int patchram_get_slot(int addr){
    int slot;
    for (slot=0; slot < PATCHRAM_SLOTS; slot++){
        //Reuse existing patchram slot for addr
        if (patchram_address_table[slot] == addr >> 2) {
            return slot;
        }
        //Get new patchram slot
        if ( !(patchram_enable[slot>>5] & (1 << (slot&0x1f)))) {
            return slot;
        }
    }
    return -1;
}

void write_code(uint32_t addr, uint32_t data) {
    uint32_t slot = patchram_get_slot(addr);
    if (slot != -1) {
        patchram_address_table[slot] = addr >> 2;
        patchram_data_table[slot] = data;
        patchram_enable[slot>>5] |= (1 << (slot&0x1f));
    }
}

/*
Not needed
void write_code_undo(uint32_t addr) {
    uint32_t slot = patchram_get_slot(addr);
    if (slot != -1)
        patchram_enable[slot>>5] &= ~(1 << (slot&0x1f));
}
*/

#endif
