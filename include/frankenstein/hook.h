#ifndef __HOOK_H
#define __HOOK_H

#include <stddef.h>
#include <stdint.h>

/*
In emulation, we can directly write to code
*/
#ifdef FRANKENSTEIN_EMULATION
    #define write_code(addr, value) *(uint32_t *)(addr) = (uint32_t)(value);
#endif

/*
This is used to get the address of a symbol (e.g. function)
without the need of declaring it first in C
*/
#define get_symbol_address(func, addr) {                    \
    asm("ldr %0, ="#func"\n"                                \
        "b get_symbol_address_ltorg_end_%=\n"               \
        ".LTORG\n"                                          \
        "get_symbol_address_ltorg_end_%=:": "=r" (addr));   \
}

/*
patch code with "bx lr"
*/
void patch_return_thumb(size_t func) {
    size_t orig = *(size_t *)(func&~1);
    if (~func & 0x2) { /* aligned */
        write_code( (func&~3) , 0x00004770 | (orig & 0xffff0000));
    } else { /* misaligned */
        write_code( (func&~3) , 0x47700000 | (orig & 0x0000ffff));
    }
}

void patch_return_arm(size_t func) {
    write_code( func , 0xe12fff1e);
}

#define patch_return(func) patch_return_offset(func, 0)
#define patch_return_offset(func, offset) { \
    uint32_t func_ptr;                      \
    get_symbol_address(func, func_ptr);     \
    func_ptr += offset;                     \
    if (func_ptr & 1)                       \
        patch_return_thumb(func_ptr);       \
    else                                    \
        patch_return_arm(func_ptr);     \
}

/*
installs a jump at a given address using 
    Thumb mode:     ldr pc, [pc]
    Arm mode:       ldr pc, [pc, #-4]
or not aligned addresses a nop is inserted to align the code
*/

void patch_jump_thumb(size_t src, size_t dest) {
    if (~src & 0x2) { /* aligned jump */
        write_code( (src & ~3)  , 0xf000f8df);
        write_code( (src & ~3)+4, dest);
    } else { /* misaligned jump */
        size_t align = *(size_t*)(src&~3);
        align = (align & 0x0000ffff) | (0xbf00<<16);
        write_code( (src & ~3)  , align);
        write_code( (src & ~3)+4, 0xf000f8df);
        write_code( (src & ~3)+8, dest);
    }
}

void patch_jump_arm(size_t src, size_t dest) {
    write_code(src    , 0xe51ff004);
    write_code(src + 4, dest);
}


#define patch_jump(src, dest) patch_jump_offset(src, dest, 0)

#define patch_jump_offset(src, dest, offset) {      \
    uint32_t src_ptr;                               \
    get_symbol_address(src, src_ptr);               \
    src_ptr += offset;                              \
    if (src_ptr & 1)                                \
        patch_jump_thumb(src_ptr, (size_t) dest);   \
    else                                            \
        patch_jump_arm(src_ptr, (size_t) dest);     \
}


/*
Transparent hooks
*/

/*
Struct to decode the saved registers on the stack    
*/
struct __attribute__((packed))saved_regs {
    uint32_t sp,r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,lr,pc;
};

#ifdef FRANKENSTEIN_EMULATION
    #define max_hooks 256
#else
    #define max_hooks 32
#endif

#ifndef FRANKENSTEIN_EMULATION
    uint32_t get_int(); asm("get_int: mrs r0, PRIMASK; CPSID I; bx lr");
    void set_int(uint32_t); asm("set_int: msr PRIMASK, r0; bx lr");
#endif


//As we do not know where we come from, we need this code for each installed hook
#define hook_code_size 12
char hook_code[] =  "\x81\xb0"          //sub sp,4
                    "\x2d\xe9\xff\x5f"  //push {r0-r12,lr}
                    "\x02\x48"          //ldr r0, [pc, #8]
                    "\xdf\xf8\x00\xf0"; //ldr pc, [pc]

//This struct holds the hook parameters as well as some hooking code
struct hook {
    char code[hook_code_size];
    void (*handler)(void *, void *);
    struct hook *self;
    void (*pre_hook)(struct saved_regs* regs, void *arg);
    uint32_t (*post_hook)(uint32_t retval, void *arg);
    uint32_t backup_lr;
    uint32_t target;
    void *arg;
    uint32_t code_orig[3];
};

//List of installed hooks
struct hook hooks[max_hooks];
int installed_hooks = 0;

void pre_hook_handler();
void post_hook_handler();

void install_hook(struct hook *hook) {
    uint32_t x = hook->target;

    //backup code
    hook->code_orig[0] = *(uint32_t*) ((x&~3)  );
    hook->code_orig[1] = *(uint32_t*) ((x&~3)+4);
    hook->code_orig[2] = *(uint32_t*) ((x&~3)+8);

    if (hook->target & 1)
        patch_jump_thumb(hook->target, (size_t) hook | 1);
    else
        patch_jump_arm(hook->target, (size_t) hook | 1);
}

void uninstall_hook(struct hook *hook) {
    uint32_t x = hook->target;
    //aligned jump
    if (~x & 0x2) {
        write_code( (x&~3)  , hook->code_orig[0]);
        write_code( (x&~3)+4, hook->code_orig[1]);

    //misaligned jump
    } else {
        write_code( (x&~3)  , hook->code_orig[0]);
        write_code( (x&~3)+4, hook->code_orig[1]);
        write_code( (x&~3)+8, hook->code_orig[2]);
    }
}

//This method actually installs a hook
//We declare the symbol locally to avoid unecesarry declarations

#define add_hook(target, pre_hook, post_hook, arg) {    \
    void *target_ptr;                                   \
    get_symbol_address(target, target_ptr)              \
    __add_hook(target_ptr, pre_hook, post_hook, arg);   \
}

struct hook *__add_hook(void *target, void (*pre_hook)(struct saved_regs* regs, void *arg), uint32_t (*post_hook)(uint32_t retval, void *arg), void *arg) {
    if (installed_hooks+1 >= max_hooks) {
        #ifdef print
            print("too many hooks\n");
        #endif
        return NULL;
    }

    //initialize hook struct with code
    for (int i=0; i < hook_code_size; i++) hooks[installed_hooks].code[i] = hook_code[i];

    hooks[installed_hooks].self = &hooks[installed_hooks];
    hooks[installed_hooks].backup_lr = 0x00;
    #ifdef FRANKENSTEIN_EMULATION
        //in emulation our code is not compiled as thumb
        hooks[installed_hooks].handler = &pre_hook_handler;
    #else
        hooks[installed_hooks].handler = (void (*)(void *, void *)) ((uint32_t)&pre_hook_handler | 1);
    #endif

    #ifdef FRANKENSTEIN_EMULATION
        hooks[installed_hooks].pre_hook = pre_hook;
        hooks[installed_hooks].post_hook = post_hook;
    #else
        hooks[installed_hooks].pre_hook =  (pre_hook) ? (void (*)(struct saved_regs *, void *)) ((uint32_t)pre_hook | 1) : NULL;
        hooks[installed_hooks].post_hook =  (post_hook) ? (uint32_t (*)(uint32_t, void *)) ((uint32_t)post_hook | 1) : NULL;
    #endif

    hooks[installed_hooks].arg = arg;
    hooks[installed_hooks].target = (uint32_t)target;

    install_hook(&hooks[installed_hooks]);

    return &hooks[installed_hooks++];
}

//c level code for pre and post hooks
void pre_hook(struct hook *hook, struct saved_regs *regs) {
    #ifndef FRANKENSTEIN_EMULATION
        int i = get_int();
    #endif

    //restore function
    uninstall_hook(hook);

    //calculate sp
    regs->sp = ((uint32_t)regs)+sizeof(struct saved_regs);


    //prepare call to target
    regs->pc = hook->target;

    //call payload
    if(hook->pre_hook) hook->pre_hook(regs, hook->arg);


    if (!hook->backup_lr) {
        //set handler for post_hook
        #ifdef FRANKENSTEIN_EMULATION
            hook->handler = (void (*)(void *, void *)) ((uint32_t)&post_hook_handler);
        #else
            hook->handler = (void (*)(void *, void *)) ((uint32_t)&post_hook_handler | 1);
        #endif

        //save lr
        hook->backup_lr = regs->lr;
        regs->lr = (uint32_t)(hook)|1;
    }

    #ifndef FRANKENSTEIN_EMULATION
        set_int(0);
    #endif

}

void post_hook(struct hook *hook, struct saved_regs *regs) {
    #ifndef FRANKENSTEIN_EMULATION
        int i = get_int();
    #endif

    //calculate sp
    regs->sp = ((uint32_t)regs)+sizeof(struct saved_regs);

    //call payload
    if(hook->post_hook) regs->r0 = hook->post_hook(regs->r0, hook->arg);

    //hook handler is now for pre hook again
    #ifdef FRANKENSTEIN_EMULATION
        hook->handler = (void (*)(void *, void *)) ((uint32_t)&pre_hook_handler);
    #else
        hook->handler = (void (*)(void *, void *)) ((uint32_t)&pre_hook_handler | 1);
    #endif

    //load lr
    regs->lr = hook->backup_lr;
    hook->backup_lr = 0x00;

    //reinstall hook
    install_hook(hook);

    #ifndef FRANKENSTEIN_EMULATION
        set_int(0);
    #endif
}

//as we mess up with the stack, some code needs to be in assembly
asm(
"pre_hook_handler:\n"
    "sub sp, #4\n"
    "mov r1, sp\n"
    "bl pre_hook\n"
    "add sp, #4\n"
    "pop {r0-r12,lr}\n"
    "pop {pc}\n"


"post_hook_handler:"
    "sub sp, #4\n"
    "mov r1, sp\n"
    "bl post_hook\n"
    "add sp, #4\n"
    "pop {r0-r12,lr}\n"
    "add sp, #4\n"
    "bx lr\n"
);

#ifdef print
#ifdef print_ptr
    #define trace(func, n, hasret) add_hook(func, &trace_prehook_##n, &trace_posthook_##hasret, #func);

    #define jump_trace(func, target, n, hasret){    \
        patch_jump(func, target)                    \
        trace(func, n, hasret) }
        
    #define trace_color "\033[;36m"
    void trace_prehook_0(struct saved_regs *regs, void *func_name) {  \
        print(trace_color);
        print("lr=");
        print_ptr(regs->lr);
        print(" ");
        puts(func_name);
        print("(");
        print(")\033[;00m");
    }

    void trace_prehook_1(struct saved_regs *regs, void *func_name) {  \
        print(trace_color);
        print("lr=");
        print_ptr(regs->lr);
        print(" ");
        puts(func_name);
        print("(");
        print_ptr(regs->r0);
        print(")\033[;00m");
    }

    void trace_prehook_2(struct saved_regs *regs, void *func_name) {  \
        print(trace_color);
        print("lr=");
        print_ptr(regs->lr);
        print(" ");
        puts(func_name);
        print("(");
        print_ptr(regs->r0);
        print(", ");
        print_ptr(regs->r1);
        print(")\033[;00m");
    }

    void trace_prehook_3(struct saved_regs *regs, void *func_name) {  \
        print(trace_color);
        print("lr=");
        print_ptr(regs->lr);
        print(" ");
        puts(func_name);
        print("(");
        print_ptr(regs->r0);
        print(", ");
        print_ptr(regs->r1);
        print(", ");
        print_ptr(regs->r2);
        print(")\033[;00m");
    }

    void trace_prehook_4(struct saved_regs *regs, void *func_name) {  \
        print(trace_color);
        print("lr=");
        print_ptr(regs->lr);
        print(" ");
        puts(func_name);
        print("(");
        print_ptr(regs->r0);
        print(", ");
        print_ptr(regs->r1);
        print(", ");
        print_ptr(regs->r2);
        print(", ");
        print_ptr(regs->r3);
        print(")\033[;00m");
    }


    uint32_t trace_posthook_true(uint32_t retval, void *func_name) {
        print(trace_color " = ");
        print_ptr(retval);
        print(";\n");
        print("\033[;00m");
        return retval;
    }

    uint32_t trace_posthook_false(uint32_t retval, void *func_name) {
        print(trace_color ";\n\033[;00m");
        return retval;
    }

    //This seems to have changed in gcc 10.1

    uint32_t trace_posthook_1(uint32_t retval, void *func_name) {
        trace_posthook_true(retval, func_name);
    }
    uint32_t trace_posthook_0(uint32_t retval, void *func_name) {
        trace_posthook_false(retval, func_name);
    }

#endif
#endif

#endif
