#include <frankenstein.h>

#define fail(x)                         \
    print("\033[31m"x"\033[0m\n");      \
    exit(-1);                           \

#ifdef TEST_THUMB
 __attribute__((target("thumb")))
#endif
void patchme_return() {
    fail("This should never be called")
}

#ifdef TEST_THUMB
 __attribute__((target("thumb")))
#endif
int patchme_jump() {
    fail("This should never be called")

    return 0;
}

int patchme_hook_called = 0;

#ifdef TEST_THUMB
 __attribute__((target("thumb")))
#endif
int patchme_hook(int arg) {
    patchme_hook_called = 1;
    if (!arg) {
        fail("Wrong argument");
    }
    return 0;
}


void test() {
    print("Testing patch_return\n");
    patchme_return();
    print("\033[32mOk\033[0m\n");

    print("Testing patch_jump\n");

    if (!patchme_jump()) {
        fail("Wrong return value")
    }
    print("\033[32mOk\033[0m\n");

    print("Testing hook\n");
    if (!patchme_hook(0)) {
        fail("Wrong ret value");
    }
    if (!patchme_hook_called) {
        fail("Original function not called");
    }
    print("\033[32mOk\033[0m\n");

    print("\033[32mDone\033[0m\n");
}

int _start() { 
    test();
    exit(0);
}
