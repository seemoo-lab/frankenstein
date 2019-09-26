#include <frankenstein/BCMBT/patching/hciio.h>

int _start() {
    print("hello");
    print("\\o/\nfrom firmware\n");
    print_var(_start);
    return 0;
}
