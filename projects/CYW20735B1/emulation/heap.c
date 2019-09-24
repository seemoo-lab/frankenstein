#include <frankenstein/utils.h>
#include "common.h"
#include "dynamic_memory.h"



/*
malloc & free
*/
//extern void *malloc(int size);
extern void free(void *buff);

struct heap_chunk {
    size_t size;
    struct heap_chunk *next;
    char data[];
};


void heap_show_free_list(struct heap_chunk *free_list) {
    struct heap_chunk *current;
    print("free list: "); print_ptr(free_list);
    for (current = free_list; current->next; current = current->next) {
        print(" -> "); print_ptr(current->next); print(" (");print_ptr(current->size); print(")");
    }
    print("\n");
}





void **__rt_heap_descriptor();

void _start() {
    patch_code();
    //for (int i=0; i < 8; i++) print_var(dynamic_memory_AllocateOrDie(32));

    //iterate heap
    struct dynamic_memory_pool *pool = g_dynamic_memory_AllPools;
    void **free_list;
    //clear_heap();
    //check_heap();

    do {
        print("----------------------------------------\n");
        print_var(pool);
        print_var(pool->size);
        print_var(pool->block_start);
        print_var(pool->free_list);
        print_var(pool->available);
        hexdump(pool->unknwn, 64);
        print("\n");
        print_var(dynamic_memory_AllocateOrDie(32));
        print_var(pool->available);
        hexdump(pool->unknwn, 64);
        print("\n");
        free_list = pool->free_list;
        print_var(dynamic_memory_AllocateOrDie(32));
        print_var(pool->available);
        hexdump(pool->unknwn, 64);
        print("\n");
        free_list = pool->free_list;
        do {
            print_var(free_list);
            free_list = *free_list;
        } while(free_list);

        pool = pool->next;

    } while (pool);

    //*((int *) 0x220f20) = 0x4142;
    //while(1) print_var(dynamic_memory_AllocateOrDie(200));
    print_var(dynamic_memory_AllocateOrDie(0x0110));

    exit(0);
}
