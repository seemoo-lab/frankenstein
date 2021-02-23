#include <stdint.h>

/*
By Overwriting the fault handlers, we can
iterate over the whole address space without crashing the device.
This can be used to map the memory
*/

void map_memory_fault_handler();
void map_memory_main(uint32_t start);
void map_memory_xmit(uint32_t *data);

uint32_t map_memory_start = 0;

asm("map_memory_fault_handler:\n"
    "mrs r0, psp\n"
    "ldr r1, =map_memory_fault\n"
    "str r1, [r0, #24]\n"           //overwrite stored pc with map_memory_fault
    "mov lr,0xFFFFFFFD\n"           //return from interrupt
    "bx lr\n");


asm("map_memory_main:\n"
    "mov r4, r0\n"                  //current address

    "map_memory_loop:\n"
    "ldr r5, [r4]\n"                //try to acces address
    "mov r0, r4\n"
    "bl hci_xmit_map_report\n"      //send address
    "add r4, #0x100\n"              //increment address by one word
    "b map_memory_loop\n"

    "map_memory_fault:\n"
    "mov r0, r4\n"
    "orr r0, #1\n"                  //send adddress with lsb set on fault
    "bl hci_xmit_map_report\n"      //send address
    "add r4, #0x100\n"              //scan steps
    "b map_memory_loop\n"

    "bx lr\n");


void map_memory() {
    uint32_t handler = (uint32_t)&map_memory_fault_handler;
    write_code(0x0c, handler|1); //hard fault
    write_code(0x04, handler|1); //reset
    write_code(0x08, handler|1); //nmi
    write_code(0x10, handler|1); //memfault
    write_code(0x14, handler|1); //bus fault
    write_code(0x18, handler|1); //usage_fault


    hci_xmit_map_report(0xffffffff); //signal start
    map_memory_main(map_memory_start);
}
