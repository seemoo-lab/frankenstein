#ifndef _COMMON_H
#define _COMMON_H
void cont();

#define EMULATED

//utils
int ret1() { return 1; }
int ret0() { return 0; }
void die() {  print_caller(); print(" die();\n"); exit(-1);}
void clean_exit() {  exit(0);}

#include <frankenstein/xmit_state_emu.h>
#include "fwdefs.h"
#include <frankenstein/hook.h>
#include "hci.h"
#include "lm.h"
#include "timer.h"
#include "dynamic_memory.h"

#include <frankenstein/threadx/threading.h>

/*
Hook for Peripheral UART
*/
void puart_write_hook(char c) {
    print("\033[;34m");
    write(2, &c, 1);
    print("\033[;00m");
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
This
*/
//TODO move to variables in fwdefs.h
void print_thrd_bcmbt(uint32_t thrd) {
    switch (thrd) {
        case 0x20C1D8: //referenced by _tx_thread_create but has no global name
            print("bttransport");
            break;

        case 0x20DA8C: // g_bthci_lm_thread_Thread:
            print("lm");
            break;

        case 0x20C2F8: //g_pmu_idle_IdleThread:
            print("idle");
            break;

        case 0x20BF9C: // g_mpaf_thread_cb:
            print("mpaf");
            break;

        case 0x20E320: // g_aa_thread_Thread
            print("aa");
            break;

        default:
            print_ptr(_tx_thread_current_ptr);
    }
}


/*
    global code patching
*/

// idle loop is broken when a crash happens in 0xfffffffd
//#define idle_loop (*(uint32_t*)0x024de64) //TODO not sure whre this value came from?
//#define idle_loop (*(uint32_t*)0x2003d4)
#define define_idle_loop(addr)  int asd = addr;
//define idle_loop (* (void(**)(void)) (addr))

#define idle_loop_ptr 0x2003d4


uint32_t _tx_v7m_get_and_disable_int();
void _tx_v7m_set_int(uint32_t);
uint32_t _tx_v7m_get_int();

uint32_t get_int();
void set_int(uint32_t);


void bcs_pmuTimeToSleepCallback();
void bcs_pmuSleepEnable();

void synch_GetXPSRExceptionNumber();
void osapi_interruptContext();
void btclk_AdvanceNatClk_clkpclk();

void patch_code() {
    patch_return(bcs_pmuSleepEnable);

    //ThreadX basics
    patch_return(_tx_v7m_get_and_disable_int);
    patch_return(_tx_v7m_set_int);
    patch_return(_tx_v7m_get_int);
    patch_return(get_int);
    patch_return(set_int);

    patch_jump(_tx_thread_system_return, _tx_thread_system_return_hook); // TODO i think this might be CYW20735 only in threading.h
    //patch_return(_tx_thread_context_restore); // TODO definitely some trouble maker but this is not the fix ... leads to permanent loop of bcs_kernelRxDone(); and probably task switches are disabled
    //patch_jump(_tx_thread_context_restore, _tx_thread_system_return); //TODO definitely not as it should be, but dies later...

    patch_return(osapi_interruptContext);
    patch_jump(osapi_interruptContext, _tx_thread_system_return);
    patch_return(osapi_interruptContext);

    //Functions that we do not support and can disable without severe side effects
    patch_jump(synch_GetXPSRExceptionNumber, ret0); //FIXME this is weird, but just using "patch_return" here breaks 2
                                                    // bytes in function before, which is synch_AtomicAdd. ret0 works, though.
    patch_return(btclk_DelayXus);
    patch_return(btclk_Wait4PclkChange);
    patch_return(btclk_AdvanceNatClk_clkpclkHWWA);
    patch_return(btclk_AdvanceNatClk_clkpclk);

    //Show thread names
    print_thrd = print_thrd_bcmbt;

    //Relplace return from interrupt addr with exit
    idle_loop = clean_exit;

    //Watchdog HW Reset
    patch_jump(&wdog_generate_hw_reset, &die);
    //Enable Peripheral UART
    patch_jump(&puart_write, &puart_write_hook);
    //Trace dbfw Assert Fatals
    trace(dbfw_assert_fatal, 1, false);

    //Disable NV RAM
    patch_return(wiced_hal_read_nvram);
    trace(wiced_hal_read_nvram, 4, true);
    patch_return(wiced_hal_write_nvram);
    trace(wiced_hal_write_nvram, 4, true);

    //Enable Osapi Timers
    add_timer_hooks();

    hci_install_hooks();

    add_lm_hooks();


    //add heap sanitizer
    init_dynamic_memory_sanitizer();
}

#endif
