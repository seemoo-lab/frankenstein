#ifndef _COMMON_H
#define _COMMON_H
void cont();

#define EMULATED

//utils
int ret1() { return 1; }
int ret0() { return 0; }
//int brk() {}

#include <frankenstein/xmit_state_emu.h>
#include "fwdefs.h"
#include <frankenstein/hook.h>
#include "hci.h"
#include "lm.h"
#include "timer.h"
#include "dynamic_memory.h"

#include <frankenstein/threadx/threading.h>

/*
Hook for PUART
*/
void puart_write_hook(char c) {
    print("\033[;34m");
    write(2, &c, 1);
    print("\033[;00m");
}


/*
NVRAM Hooks
*/
void wiced_hal_read_nvram_hook(int a1, int a2, int a3, int a4) {
    print("wiced_hal_read_nvram_hook(");
    print_ptr(a1); print(", ");
    print_ptr(a2); print(", ");
    print_ptr(a3); print(", ");
    print_ptr(a4); print(")\n");
}


void wiced_hal_write_nvram_hook(int a1, int a2, int a3, int a4) {
    print("wiced_hal_write_nvram_hook(");
    print_ptr(a1); print(", ");
    print_ptr(a2); print(", ");
    print_ptr(a3); print(", ");
    print_ptr(a4); print(")\n");
}


/*
Queu
*/

//probably mpaf timer/event
struct queue_entry {
    void *next;
    int maybe_flags;
    void *sometimes_callback;
    void *callback_arg;
    char unknwn[];
} *queue_entry;

void msgqueue_Put_hook(struct saved_regs *regs, void *arg) {
    void *queue = (void *)regs->r0;
    struct queue_entry *item = (void *)regs->r1;
    print_caller();
    print(" msgqueue_Put_hook(");
    print_ptr(queue);
    print(", ");
    print_ptr(item);
    print(");\n");
    print("     ");print_var(item->maybe_flags)
    print("     ");print_var(item->sometimes_callback)
    print("     ");print_var(item->callback_arg)
    print("     "); hexdump(item, 32);
}

/*
threading
*/

void print_thrd(int thrd) {
    switch (thrd) {
        case 0x249e58: //missing in patch.elf
            print("bttransport");
            break;

        case 0x20beb4:
            print("lm");
            break;

        case 0x20a578:
            print("idle");
            break;

        case 0x20a1fc:
            print("mpaf")
            break;

        default:
            print_ptr(_tx_thread_current_ptr);
    }
}


/*
    global code patching
*/
void die() {  print_caller(); print(" die();\n"); exit(-1);}


void patch_code() {
    //Functions, we do not support
    patch_return(0xa4402);  //tx_v7m_get_and_disable_int
    patch_return(0x1094d4); //_tx_v7m_set_int
    patch_return(0xa43fd); //_tx_v7m_get_int
    patch_return(0xa43ee);  //synch_GetXSPRExceptionNum
    patch_return(0x63660);//osapi_interruptContext
    patch_return(0x20ffb2); //get_and_disable_int 2nd ed?!
    patch_return(btclk_DelayXus);
    patch_return(btclk_Wait4PclkChange);
    patch_return(0x0009b134);


    //Watchdog HW Reset
    patch_jump(&wdog_generate_hw_reset, &die);
    //Enable Peripheral UART
    patch_jump(&puart_write, &puart_write_hook);
    //Trace dbfw Assert Fatals
    trace(dbfw_assert_fatal, 1, false);

    //Disable NV RAM
    patch_jump(&wiced_hal_read_nvram, &wiced_hal_read_nvram_hook);
    patch_jump(&wiced_hal_write_nvram, &wiced_hal_write_nvram_hook);

    //Enable Multithreading
    patch_jump(&_tx_thread_system_return, &_tx_thread_system_return_hook);

    //Enable Osapi Timers
    add_timer_hooks();


    hci_install_hooks();

    add_lm_hooks();

    print_var(_tx_thread_current_ptr);

    //add heap sanitizer
    init_dynamic_memory_sanitizer();
    print_var(installed_hooks)
}

#endif
