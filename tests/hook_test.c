#include <frankenstein.h>

 __attribute__((target("thumb")))
void patchme_return() {
    print("This should never be called\n")
    exit(-1);
}

 __attribute__((target("thumb")))
int patchme_jump() {
    print("This should never be called\n")
    return 0;
}

int patchme_hook_called = 0;

 __attribute__((target("thumb")))
int patchme_hook(int arg) {
    patchme_hook_called = 1;
    if (!arg) {
        print("Wrong argument\n");
        return 1;
    }
    return 0;
}


void test() {
    print("Testing patch_return\n");
    patchme_return();

    print("Testing patch_jump\n");
    if (!patchme_jump()) {
        exit(-1);
    }

    print("Testing hook\n");
    if (!patchme_hook(0)) {
        print("Wrong ret value\n");
    }
    if (!patchme_hook_called) {
        print("Original function not called\n");
        exit(-1);
    }

    print("Done\n");
}

int _start() { 
    test();
    exit(0);
}
