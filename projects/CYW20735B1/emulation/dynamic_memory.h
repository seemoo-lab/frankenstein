#ifndef DYNAMIC_MEMORY_H
#define DYNAMIC_MEMORY_H


#include "common.h"
#include <frankenstein/BCMBT/dynamic_memory.h>

void init_dynamic_memory_sanitizer() {
    //clear_heap();

    dynamic_memory_check_free_list("Load\n", 0);

    dynamic_memory_sanitize_trace_function(inqfilter_isBdAddrRegistered, 1, false);
    dynamic_memory_sanitize_trace_function(inqfilter_registerBdAddr, 1, false);

    dynamic_memory_sanitize_trace_function(dynamic_memory_AllocateOrDie, 1, true);
    dynamic_memory_sanitize_trace_function(dynamic_memory_Release, 1, true);
    dynamic_memory_sanitize_trace_function(dynamic_memory_AllocatePrivate, 3, true);

    dynamic_memory_sanitize_trace_function(memcpy_r, 3, false);
    dynamic_memory_sanitize_trace_function(utils_memcpy8, 3, false);
    dynamic_memory_sanitize_trace_function(sfi_memcpy, 3, false);
    dynamic_memory_sanitize_trace_function(utils_memcpy10, 3, false);
    dynamic_memory_sanitize_trace_function(utils_memcpy8_postinc, 3, false);
    dynamic_memory_sanitize_trace_function(__aeabi_memcpy, 3, false);
    dynamic_memory_sanitize_trace_function(utils_memcpy3dword, 3, false);
    //dynamic_memory_sanitize_trace_function(__rt_memcpy_w, 3, false);
    //dynamic_memory_sanitize_trace_function(__aeabi_memcpy8, 3, false);
    dynamic_memory_sanitize_trace_function(__aeabi_memcpy4, 3, false);
    dynamic_memory_sanitize_trace_function(__ARM_common_memcpy4_5, 3, false);
    dynamic_memory_sanitize_trace_function(__ARM_common_memcpy4_10, 3, false);
    dynamic_memory_sanitize_trace_function(mpaf_memcpy, 3, false);
    dynamic_memory_sanitize_trace_function(memcpy, 3, false);
    dynamic_memory_sanitize_trace_function(_memcpy_lastbytes, 3, false);
    dynamic_memory_sanitize_trace_function(_memcpy_lastbytes_aligned, 3, false);
    //dynamic_memory_sanitize_trace_function(__rt_memcpy, 3, false);
}

#endif
