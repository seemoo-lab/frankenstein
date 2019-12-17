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


void _start() {
    //iterate heap
    struct dynamic_memory_pool *pool = g_dynamic_memory_AllPools;
    void **free_list;

    patch_code();
    init_dynamic_memory_sanitizer();

    do {
        print("----------------------------------------\n");
        print_var(pool);
        print_var(pool->size);
        print_var(pool->block_start);
        print_var(pool->free_list);
        print_var(pool->available);
        free_list = pool->free_list;
        do {
            print_var(free_list);
            free_list = *free_list;
        } while(free_list);

        pool = pool->next;

    } while (pool);

    void *ptr = dynamic_memory_AllocateOrDie(32);
    memset(ptr, 0x00, 32);
    dynamic_memory_Release(ptr);

    exit(0);
}
