#ifndef _COMMON_XMIT_STATE_EMU_H
#define _COMMON_XMIT_STATE_EMU_H

#include <elf.h>
#include <frankenstein/utils.h>

int xmited = 0;

void xmit_memory_emu(char *fname) {
    if (xmited++) return;
    int lr;
    asm("mov %0, lr\n" : "=r" (lr));
    print_var(lr);

    print("xmiting state to "); print(fname); print("\n");

    //copy file
    int c;
    int src = open("/proc/self/exe", O_RDONLY);
    int dst = open(fname, O_RDWR|O_CREAT, 0777);
    int n_read, n_total=0;
    while ((n_read = read(src, &c, 4))>0) write(dst, &c, n_read), n_total += n_read;
    close(src); close(dst);

    //mapping ELF
    dst = open(fname, O_RDWR|O_CREAT);
    void *elf = mmap(0, n_total, PROT_READ|PROT_WRITE, MAP_SHARED, dst, 0);
    print_var(elf);

    //Entrypoint
    Elf32_Ehdr *ehdr = elf;
    ehdr->e_entry = lr;

    //Update Memory regions
    Elf32_Phdr *phdr = elf + ehdr->e_phoff;
    for (int i=0; i < ehdr->e_phnum ; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            print("updating "); print_ptr(phdr[i].p_vaddr); print("\n");
            for (int j=0; j < phdr[i].p_filesz; j++) 
                *(char*)(elf + phdr[i].p_offset + j) = *(char*)(phdr[i].p_vaddr+j);
            //memcpy(elf + phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_filesz);
        }
    }



    print("done\n");
    exit(0);
}


// Requires Stack to be in the elf file
// Fix would be void _start(){ asm("ldr sp, =stack_end"); main(); }
void xmit_state_emu(char *fname);
asm("xmit_state_emu:"
    "push {r0-r12,lr}\n"
    "ldr r1, =saved_regs_emu\n"
    "str sp, [r1]\n"

    "bl xmit_memory_emu\n"

    "ldr r1, =saved_regs_emu\n"
    "ldr sp, [r1]\n"
    "pop {r0-r12,lr}\n"
    "bx lr\n"
    ".LTORG\n"
    "saved_regs_emu:\n"
    ".word");

#endif
