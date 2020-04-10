#include <frankenstein/utils.h>
#include <frankenstein/hook.h>
#include <frankenstein/xmit_state_emu.h>

void inqfilter_init();
void inqfilter_registerBdAddr(char *, int);
void get_int();
void set_int();

#include <sys/stat.h>
#include <fcntl.h>



void do_exit() {
   exit(0); 
}
void *mm_allocACLDown();
void dbfw_assert_alert();

#include <frankenstein/BCMBT/dynamic_memory.h>

void _start() {
    //patch_code();

    patch_return(get_int)
    patch_return(set_int)
    patch_return(0x17782e)
    patch_return(0x1779b2)
    patch_return(0x750)

    trace(dbfw_assert_alert, 2, false);
    trace(dynamic_memory_AllocatePrivate, 2, false);

    char bd_addr[6] = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46};

    inqfilter_init();
    for (unsigned char i=0; i < 0xff; i++) {
        bd_addr[0] = i;
        inqfilter_registerBdAddr(bd_addr, 0);
        print_var(i);
    }

    bd_addr[1] = 0x42;
    for (unsigned char i=0; i < 0xff; i++) {
        bd_addr[0] = i;
        inqfilter_registerBdAddr(bd_addr, 0);
        print_var(i);
    }
    dynamic_memory_check_free_list("test", 0);

    show_heap();
    exit(0);
    
}
