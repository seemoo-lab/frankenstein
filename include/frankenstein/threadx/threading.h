#ifndef __FRANKENSTEIN_THREADX_THREADING_H
#define  __FRANKENSTEIN_THREADX_THREADING_H

#include <frankenstein/utils.h>

/*
This file implements the ThreadX context switch, as observed on the CYW20735.
This is required to emulate multi threading in the emulator.
_tx_thread_current_ptr is the current running thread, whereas _tx_thread_execute_ptr
is the next thread, that was determined by the scheduler.
After scheduling is done, _tx_thread_system_return_hook is invoked to perform the switch
between those threads. This function is re-implemented here.
*/


void _tx_thread_system_return(void);
extern void *_tx_thread_current_ptr;
extern void *_tx_thread_execute_ptr;
void (*print_thrd)(void *) = NULL;

/*
Print message about the context switch
*/
void _tx_thread_system_return_debug() {

    print("\033[;31mContext switch ");
    if (print_thrd)
        print_thrd(_tx_thread_current_ptr);
    else
        print_ptr(_tx_thread_current_ptr);

    print(" -> ");

    if (print_thrd)
        print_thrd(_tx_thread_execute_ptr);
    else
        print_ptr(_tx_thread_execute_ptr);
    print("\033[;00m\n");
}

/*
In some cases scheduling is performed, but _tx_thread_system_return
is not called.
In the idle_loop, we can therefore enforce a context switch if desired.
*/
void contextswitch() {
    if (_tx_thread_current_ptr == _tx_thread_execute_ptr)
        return;
    _tx_thread_system_return();
}

/*
Saves the current stack pointer int to _tx_thread_current_ptr and
loads sp from _tx_thread_execute_ptr
In addition we set the current thread to the execute one
*/

uint32_t _tx_thread_system_return_exchange_sp(uint32_t sp) {
    *(uint32_t *)(_tx_thread_current_ptr+8) = sp;
    sp = *(uint32_t*) (_tx_thread_execute_ptr+8); 
    _tx_thread_current_ptr = _tx_thread_execute_ptr;
    return sp;
}

/*
ThreadX is using a SuperVisor Call to trigger a context switch.
The handler was re-implemented according to the CYW20735B1.
As it is a interrupt, what we do not support, we have to take
care of the stack layout our selves.
*/
void _tx_thread_system_return_hook(void);
asm(
        "_tx_thread_system_return_hook:\n"

        //save registers
        "sub sp, #20\n"
        "push {r0-r3,r12}\n"    //Interrupt frame
        "push {r4-r11}\n"       //SVC handler registers
        "str lr, [sp, #52]\n"   //location of lr

        //execute our hook payload
        "bl _tx_thread_system_return_debug\n"

        //swap th
        "mov r0, sp\n"
        //swap threads and sp
        "bl _tx_thread_system_return_exchange_sp\n"

        //loat registers from next thread
        "ldr lr, [r0, #52]\n" //get saved lr
        "mov sp, r0\n"
        "pop {r4-r11}\n"    //SVC handler regs
        "pop {r0-r3,r12}\n" //Interrupt frame
        "add sp, #20\n"

        //return
        "bx lr\n"
);

/*
After executing a firmware state, we will perform a return from interrupt
The return address on the stack will be 0xfffffffd
idle_loop_ptr is the address of this return address on the stack
It will be overwritten with a pointer to a custom function to handle this state
*/

#define idle_loop (* (void(**)(void)) (idle_loop_ptr))


#endif
