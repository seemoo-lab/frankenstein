#ifndef DYNAMIC_MEMORY_H
#define DYNAMIC_MEMORY_H


#include "common.h"
void *memcpy_r(void *dest, const void *src, size_t n);
void *utils_memcpy8(void *dest, const void *src, size_t n);
void *sfi_memcpy(void *dest, const void *src, size_t n);
void *utils_memcpy10(void *dest, const void *src, size_t n);
void *utils_memcpy8_postinc(void *dest, const void *src, size_t n);
void *__aeabi_memcpy(void *dest, const void *src, size_t n);
void *utils_memcpy3dword(void *dest, const void *src, size_t n);
void *__rt_memcpy_w(void *dest, const void *src, size_t n);
void *__aeabi_memcpy8(void *dest, const void *src, size_t n);
void *__aeabi_memcpy4(void *dest, const void *src, size_t n);
void *__ARM_common_memcpy4_5(void *dest, const void *src, size_t n);
void *__ARM_common_memcpy4_10(void *dest, const void *src, size_t n);
void *mpaf_memcpy(void *dest, const void *src, size_t n);
void *memcpy(void *dest, const void *src, size_t n);
void *_memcpy_lastbytes(void *dest, const void *src, size_t n);
void *_memcpy_lastbytes_aligned(void *dest, const void *src, size_t n);
void *__rt_memcpy(void *dest, const void *src, size_t n);

void *__rt_memmove_w(void *dest, const void *src, size_t n);
void *memmove(void *dest, const void *src, size_t n);
void *__memmove_aligned(void *dest, const void *src, size_t n);
void *mpaf_memmove(void *dest, const void *src, size_t n);
void *__rt_memmove(void *dest, const void *src, size_t n);
void *__memmove_lastfew(void *dest, const void *src, size_t n);
void *__memmove_aligned(void *dest, const void *src, size_t n);
void *__aeabi_memmove8(void *dest, const void *src, size_t n);
void *__aeabi_memmove4(void *dest, const void *src, size_t n);
void *__aeabi_memmove(void *dest, const void *src, size_t n);
void *__memmove_lastfew_aligned(void *dest, const void *src, size_t n);

void *memset(void *dest, int c,  size_t n);
void *_memset(void *dest, const size_t n, int c);




struct dynamic_memory_pool {
    struct dynamic_memory_pool *next;
    short size;
    unsigned char capacity;
    unsigned char field_7;
    void *block_start;
    void *free_list;
    unsigned char available;
    unsigned char field_11;
    char unknwn[]

};
struct dynamic_memory_pool *g_dynamic_memory_AllPools;

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

void prehook_dynamic_memory_sanitizer(struct saved_regs *regs, void *_) {
    check_heap();
}

uint32_t posthook_dynamic_memory_sanitizer(uint32_t retval, void *_) {
    clear_heap();
    return retval;
}

uint32_t posthook_dynamic_memory_sanitizer_check(uint32_t retval, void *_) {
    check_heap();
    return retval;
}

void init_dynamic_memory_sanitizer() {
    clear_heap();
    add_hook(dynamic_memory_AllocatePrivate, prehook_dynamic_memory_sanitizer, posthook_dynamic_memory_sanitizer, NULL);
    add_hook(dynamic_memory_Release, prehook_dynamic_memory_sanitizer, posthook_dynamic_memory_sanitizer, NULL);
    add_hook(__rt_memcpy, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(__rt_memmove, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(utils_memcpy8, NULL, posthook_dynamic_memory_sanitizer_check, NULL);

    trace(__rt_memcpy, 3, false);
    trace(__rt_memmove, 3, false);
    trace(dynamic_memory_AllocateOrReturnNULL, 1, true);
    trace(dynamic_memory_SpecialBlockPoolAllocateOrReturnNULL, 1, true);
    trace(dynamic_memory_AllocateOrDie, 1, true);
    trace(dynamic_memory_Release, 1, false);
    trace(utils_memcpy8, 3, false);


    return;
    add_hook(memcpy_r, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(sfi_memcpy, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(utils_memcpy10, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(utils_memcpy8_postinc, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(__aeabi_memcpy, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(utils_memcpy3dword, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(__rt_memcpy_w, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(__aeabi_memcpy8, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(__aeabi_memcpy4, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(__ARM_common_memcpy4_5, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(__ARM_common_memcpy4_10, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(mpaf_memcpy, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(memcpy, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(_memcpy_lastbytes, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(_memcpy_lastbytes_aligned, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(__rt_memcpy, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(__rt_memmove_w, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(memmove, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(__memmove_aligned, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(mpaf_memmove, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(__rt_memmove, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(__memmove_lastfew, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(__aeabi_memmove8, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(__aeabi_memmove4, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(__aeabi_memmove, NULL, posthook_dynamic_memory_sanitizer_check, NULL);
    add_hook(__memmove_lastfew_aligned, NULL, posthook_dynamic_memory_sanitizer_check, NULL);

    add_hook(_memset, NULL, posthook_dynamic_memory_sanitizer_check, NULL);

    trace(_memset, 3, false);

    //return;
    trace(memcpy_r, 3, false);
    trace(utils_memcpy8, 3, false);
    trace(sfi_memcpy, 3, false);
    trace(utils_memcpy10, 3, false);
    trace(utils_memcpy8_postinc, 3, false);
    trace(__aeabi_memcpy, 3, false);
    trace(utils_memcpy3dword, 3, false);
    trace(__rt_memcpy_w, 3, false);
    trace(__aeabi_memcpy8, 3, false);
    trace(__aeabi_memcpy4, 3, false);
    trace(__ARM_common_memcpy4_5, 3, false);
    trace(__ARM_common_memcpy4_10, 3, false);
    trace(mpaf_memcpy, 3, false);
    trace(memcpy, 3, false);
    trace(_memcpy_lastbytes, 3, false);
    //trace(_memcpy_lastbytes_aligned, 3, false);
    trace(__rt_memcpy, 3, false);
    trace(__rt_memmove_w, 3, false);
    trace(memmove, 3, false);
    trace(__memmove_aligned, 3, false);
    trace(mpaf_memmove, 3, false);
    trace(__rt_memmove, 3, false);
    trace(__memmove_lastfew, 3, false);
    trace(__aeabi_memmove8, 3, false);
    trace(__aeabi_memmove4, 3, false);
    trace(__aeabi_memmove, 3, false);
    trace(__memmove_lastfew_aligned, 3, false);
    return;
}

#endif
