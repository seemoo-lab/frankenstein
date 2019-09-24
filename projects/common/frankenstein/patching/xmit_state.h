#include <frankenstein/hook.h>


/*
This function has to send the device memory to the host
It has to be re-implemented for each target
*/
void xmit_memory(struct saved_regs *regs, int cont);

/*
This function can be called at any point in time
It will send an executable state to the host
*/
void xmit_state();
void cont();


int saved_regs;
asm("xmit_state:\n"
//save registers
"push {r0-r12,lr}\n"
"ldr r0, =saved_regs\n"
"str sp, [r0]\n"
"ldr r1, =cont\n"

//xmit memory
"bl xmit_memory\n"

"cont:\n"
"ldr r0, =saved_regs\n"
"ldr sp, [r0]\n"
"pop {r0-r12,lr}\n"
"bx lr\n");
