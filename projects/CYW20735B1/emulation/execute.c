#include <frankenstein/utils.h>
#include <frankenstein/hook.h>
#include <frankenstein/xmit_state_emu.h>
#include "common.h"
#include "queue.h"


#include <sys/stat.h>
#include <fcntl.h>

void do_exit() {
   exit(0); 
}

void _start() {
    patch_code();
    idle_loop = do_exit;
    cont();
}
