#include <frankenstein/BCMBT/patching/hciio.h>
#include <frankenstein/BCMBT/patching/patchram.h>
#include <frankenstein/BCMBT/dynamic_memory.h>

//WriteRAM function
void *bt_boot_hci_WriteBytesToNonByteAddressableMemory(void *src, int len, void *dest);

//All memcpy funcs...
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


int _start() {
    dynamic_memory_check_free_list("Load", 1);
    dynamic_memory_sanitize_function(bt_boot_hci_WriteBytesToNonByteAddressableMemory);
    //dynamic_memory_sanitize_function(dynamic_memory_Release);

    dynamic_memory_sanitize_function(memcpy_r);
    dynamic_memory_sanitize_function(utils_memcpy8);
    dynamic_memory_sanitize_function(sfi_memcpy);
    dynamic_memory_sanitize_function(utils_memcpy10);
    dynamic_memory_sanitize_function(utils_memcpy8_postinc);
    dynamic_memory_sanitize_function(__aeabi_memcpy);
    dynamic_memory_sanitize_function(utils_memcpy3dword);
    dynamic_memory_sanitize_function(__rt_memcpy_w);
    dynamic_memory_sanitize_function(__aeabi_memcpy8);
    dynamic_memory_sanitize_function(__aeabi_memcpy4);
    dynamic_memory_sanitize_function(__ARM_common_memcpy4_5);
    dynamic_memory_sanitize_function(__ARM_common_memcpy4_10);
    dynamic_memory_sanitize_function(mpaf_memcpy);
    dynamic_memory_sanitize_function(memcpy);
    dynamic_memory_sanitize_function(_memcpy_lastbytes);
    dynamic_memory_sanitize_function(_memcpy_lastbytes_aligned);
    dynamic_memory_sanitize_function(__rt_memcpy);
}
