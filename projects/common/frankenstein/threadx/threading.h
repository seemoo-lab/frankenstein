
extern void * _tx_thread_current_ptr;
extern void * _tx_thread_execute_ptr;
extern void * _tx_thread_system_state;


//At this address a return from interrupt happens
//This is replaced with our idle code
#define idle_loop (*(void **)0x024de64)
void _tx_thread_system_return_hook_payload() {
    if (_tx_thread_execute_ptr == &g_pmu_idle_IdleThread) {
        print("\033[;31mIdle\033[;00m\n");
        if (idle_loop == (void *)0xfffffffd) {
            print("\033[;31mIdle, do exit\033[;00m\n");
            exit(0);
        }
    }

    print("\033[;31mContext switch ");
    print_thrd(_tx_thread_current_ptr);
    print(" -> ");
    print_thrd(_tx_thread_execute_ptr);
    print("\033[;00m\n");
}

void contextswitch() {
    if (_tx_thread_current_ptr == _tx_thread_execute_ptr)
        return;
    _tx_thread_system_return();
}

void _tx_thread_system_return_hook(void);
asm(
        "_tx_thread_system_return_hook:\n"

        //save state
        "sub sp, #20\n"
        "push {r0-r3,r12}\n" //Interrupt frame
        "push {r4-r11}\n" //SVC Handler
        "str lr, [sp, #52]\n"

        //execute our hook payload
        "push {lr}\n"
        "bl _tx_thread_system_return_hook_payload\n"
        "pop {lr}\n"

        //load thread structs
        "ldr r0, tx_thread_current_ptr\n"
        "ldr r1, [r0]\n"
        "ldr r2, tx_thread_execute_ptr\n"
        "ldr r3, [r2]\n"

        "str sp, [r1, #8]\n" //save sp to tx_thread_current_ptr

        //swap threads
        "str r3, [r0]\n"

        //restore thread
        "ldr r12, [r3, #8]\n" //get sp from tx_thread_execute_ptr
        "ldr lr, [r12, #52]\n" //get saved lr
        "mov sp, r12\n"
        //"bl brk\n"
        "pop {r4-r11}\n" //SVC Handler
        "pop {r0-r3,r12}\n" //Interrupt frame
        "add sp, #20\n"

        //return
        "bx lr\n"

        //static symbols :/
        "tx_thread_current_ptr:\n"
        ".word 0x201cec\n"
        "tx_thread_execute_ptr:\n"
        ".word 0x201cf0\n"

);

