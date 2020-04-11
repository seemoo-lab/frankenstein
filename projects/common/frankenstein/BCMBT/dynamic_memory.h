#include <stddef.h>
#include <frankenstein/hook.h>

struct dynamic_memory_pool {
    struct dynamic_memory_pool *next;
    short size;
    unsigned char capacity;
    unsigned char field_7;
    void *block_start;
    void *free_list;
    unsigned char available;
    unsigned char field_11;
    char unknwn[];
};

//list of all pools
struct dynamic_memory_pool *g_dynamic_memory_AllPools;

/*
Definitions
*/

void *dynamic_memory_AllocateOrReturnNULL(int size);
void *dynamic_memory_AllocateOrDie(int size);
void *dynamic_memory_AllocatePrivate(void *pool, int x);
void *dynamic_memory_SpecialBlockPoolAllocateOrReturnNULL(int size);
void dynamic_memory_Release(void *buff);




//Save some registers to debg crash
uint32_t dynamic_memory_sanitizer_lr = 0;
uint32_t dynamic_memory_sanitizer_r0 = 0;
uint32_t dynamic_memory_sanitizer_r1 = 0;
uint32_t dynamic_memory_sanitizer_r2 = 0;
uint32_t dynamic_memory_sanitizer_r3 = 0;

void dynamic_memory_check_free_list(char *msg, int show_regs) {
    struct dynamic_memory_pool *pool = g_dynamic_memory_AllPools;
    void **free_chunk;

    do {
        free_chunk = &pool->free_list;
        do {
            if ((size_t)*free_chunk < (size_t)pool->block_start || 
                (size_t)*free_chunk > (size_t)pool->block_start + ((pool->size+4) * pool->capacity)) {
                print("Heap Corruption Detected\n");
                print(msg);
                if (show_regs) {
                    print_var(dynamic_memory_sanitizer_lr);
                    print_var(dynamic_memory_sanitizer_r0);
                    print_var(dynamic_memory_sanitizer_r1);
                    print_var(dynamic_memory_sanitizer_r2);
                    print_var(dynamic_memory_sanitizer_r3);
                }
                print_var(pool);
                print_var(pool->block_start);
                print_var(pool->capacity);
                print_var(pool->size);
                print_var(*free_chunk);
                #ifdef FRANKENSTEIN_EMULATION
                    hexdump(free_chunk, 4);
                    print(" | ")
                    hexdump(free_chunk + 4, pool->size);
                    print("\n");
                #endif
                //Trigger crash
                ((void (*)(void))(free_chunk + 0xf0000000))();
            }
            free_chunk = *free_chunk;
        } while(*free_chunk);

        pool = pool->next;
    } while (pool);
}

void dynamic_memory_sanitizer_prehook(struct saved_regs *regs, void *arg) {
    dynamic_memory_sanitizer_lr = regs->lr;
    dynamic_memory_sanitizer_r0 = regs->r0;
    dynamic_memory_sanitizer_r1 = regs->r1;
    dynamic_memory_sanitizer_r2 = regs->r2;
    dynamic_memory_sanitizer_r3 = regs->r3;
    dynamic_memory_check_free_list("Prehook\n", (int)arg);
}

uint32_t dynamic_memory_sanitizer_posthook(uint32_t retval, void *arg) {
    dynamic_memory_check_free_list("Posthook\n", (int)arg);
    return retval;
}

#define dynamic_memory_sanitize_function(func) \
    add_hook(func, dynamic_memory_sanitizer_prehook, dynamic_memory_sanitizer_posthook, (void *)1)

#define dynamic_memory_sanitize_trace_function(func, n, hasret) {                                   \
    add_hook(func, dynamic_memory_sanitizer_prehook, dynamic_memory_sanitizer_posthook, (void *)0); \
    trace(func, n, hasret);                                                                         \
}

void show_heap() {
    struct dynamic_memory_pool *pool = g_dynamic_memory_AllPools;
    void **free_chunk;

    do {
        print_var(pool);
        print_var(pool->block_start);
        print_var(pool->capacity);
        print_var(pool->size);

        free_chunk = pool->free_list;
        do {
            print("  ");
            print_var(free_chunk);
            free_chunk = *free_chunk;
        } while(free_chunk);
        print("\n");

        pool = pool->next;
    } while (pool);

}

/*
void clear_heap() {
    struct dynamic_memory_pool *pool = g_dynamic_memory_AllPools;
    void **free_chunk;

    do {
        free_chunk = pool->free_list;
        if (!pool->free_list) {
            print("Empty Free List\n");
            print_var(pool);
            print_var(pool->block_start);
            print_var(pool->capacity);
            print_var(pool->size);
            print_var(free_chunk);
            print("\n");
            //Trigger crash
            exit(1);
        }
        do {
            //memset((int)free_chunk + 4, 0x42, pool->size);
            if ((size_t)free_chunk < (size_t)pool->block_start || 
                (size_t)free_chunk > (size_t)pool->block_start + ((pool->size+4) * pool->capacity)) {
                print("Heap Corruption Detected\n");
                print_var(pool);
                print_var(pool->block_start);
                print_var(pool->capacity);
                print_var(pool->size);
                print_var(free_chunk);
                print("\n");
                //Trigger crash
                ((void (*)(void))(free_chunk + 0xf0000000))();
            }

            for (int i=0; i < pool->size; i++) *(unsigned char *)((int)free_chunk + 4 + i) = 0x42;
            free_chunk = *free_chunk;
        } while(free_chunk);

        pool = pool->next;
    } while (pool);
}

void check_heap() {
    struct dynamic_memory_pool *pool = g_dynamic_memory_AllPools;
    void **free_chunk;

    do {
        free_chunk = pool->free_list;
        do {
            if ((size_t)free_chunk < (size_t)pool->block_start || 
                (size_t)free_chunk > (size_t)pool->block_start + ((pool->size+4) * pool->capacity)) {
                print("Heap Corruption Detected\n");
                print_var(pool);
                print_var(pool->block_start);
                print_var(pool->capacity);
                print_var(pool->size);
                print_var(free_chunk);
                print("\n");
                //Trigger crash
                ((void (*)(void))(free_chunk + 0xf0000000))();
            }
            for (int i=0; i < pool->size; i++) {
                if (((char *)free_chunk)[i+4] != 0x42) {
                    print("Heap Corruption Detected\n");
                    print_var(pool);
                    print_var(pool->size);
                    print_var(free_chunk);
                    hexdump(free_chunk, 4);
                    print(" | ");
                    hexdump(free_chunk + 4, pool->size);
                    print("\n");
                    //Trigger crash
                    ((void (*)(void))(free_chunk + 0xf0000000))();
                }
            }
            free_chunk = *free_chunk;
        } while(free_chunk);

        pool = pool->next;
    } while (pool);
}


void dynamic_memory_sanitizer_prehook(struct saved_regs *regs, void *_) {
    check_heap();
}

uint32_t posthook_dynamic_memory_sanitizer(uint32_t retval, void *_) {
    clear_heap();
    return retval;
}

uint32_t dynamic_memory_sanitizer_posthook(uint32_t retval, void *_) {
    check_heap();
    return retval;
}

*/
