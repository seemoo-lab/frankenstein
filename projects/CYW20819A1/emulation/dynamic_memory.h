#ifndef DYNAMIC_MEMORY_H
#define DYNAMIC_MEMORY_H


#include "common.h"
#include <frankenstein/BCMBT/dynamic_memory.h>


//void *memcpy_r(void *dest, const void *src, size_t n);
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




void init_dynamic_memory_sanitizer() {
    //clear_heap();

    dynamic_memory_check_free_list("Load", 0);

    dynamic_memory_sanitize_trace_function(dynamic_memory_Release, 1, false);
    dynamic_memory_sanitize_trace_function(dynamic_memory_AllocatePrivate, 3, false);

    //dynamic_memory_sanitize_trace_function(memcpy_r, 3, false);
    dynamic_memory_sanitize_trace_function(utils_memcpy8, 3, false);
    dynamic_memory_sanitize_trace_function(sfi_memcpy, 3, false);
    dynamic_memory_sanitize_trace_function(utils_memcpy10, 3, false);
    dynamic_memory_sanitize_trace_function(utils_memcpy8_postinc, 3, false);
    dynamic_memory_sanitize_trace_function(__aeabi_memcpy, 3, false);
    dynamic_memory_sanitize_trace_function(utils_memcpy3dword, 3, false);
    dynamic_memory_sanitize_trace_function(__rt_memcpy_w, 3, false);
    dynamic_memory_sanitize_trace_function(__aeabi_memcpy8, 3, false);
    dynamic_memory_sanitize_trace_function(__aeabi_memcpy4, 3, false);
    dynamic_memory_sanitize_trace_function(__ARM_common_memcpy4_5, 3, false);
    dynamic_memory_sanitize_trace_function(__ARM_common_memcpy4_10, 3, false);
    dynamic_memory_sanitize_trace_function(mpaf_memcpy, 3, false);
    dynamic_memory_sanitize_trace_function(memcpy, 3, false);
    dynamic_memory_sanitize_trace_function(_memcpy_lastbytes, 3, false);
    dynamic_memory_sanitize_trace_function(_memcpy_lastbytes_aligned, 3, false);
    dynamic_memory_sanitize_trace_function(__rt_memcpy, 3, false);
}

#endif
