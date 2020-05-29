#include <frankenstein.h>

int ret1() {return 1;}

void patchme_hook_prehook(struct saved_regs *regs, void *_) {
    regs->r0 = 1;
}

uint32_t patchme_hook_posthook(uint32_t ret, void *_) {
    return 1;
}

void test();
int _start() {
    print("Hello\n");

    size_t *ptr;
    get_symbol_address(patchme_return, ptr);
    patch_return(patchme_return);
    patch_jump(patchme_jump, ret1);
    add_hook(patchme_hook, patchme_hook_prehook, patchme_hook_posthook, NULL);

    test();

    exit(0);
}
