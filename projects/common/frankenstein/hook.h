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
patch code with "bx lr"
*/
#define patch_return(x) {                                   \
    if (~(uint32_t)(x) & 0x2) { /* aligned */               \
        write_code( ((uint32_t)(x)&~3)  ,                   \
        0x00004770 | (((uint32_t)(x))&~1) &0xffff0000);     \
    } else { /* misaligned jump */                          \
        write_code( ((uint32_t)(x)&~3)  ,                   \
        0x47700000 | (((uint32_t)(x))&~1) &0x0000ffff);     \
    }                                                       \
}

/*
installs a jump at a given address using "ldr pc, [pc]"
for not aligned addresses a nop is inserted to align the code
*/

#define patch_jump(x, func) {                               \
    if (~(uint32_t)(x) & 0x2) { /* aligned jump */          \
        write_code( ((uint32_t)(x)&~3)  , 0xf000f8df);      \
        write_code( ((uint32_t)(x)&~3)+4, func);            \
    } else { /* misaligned jump */                          \
        uint32_t align = *(uint32_t*)((uint32_t)(x)&~3);    \
        align = (align & 0x0000ffff) | (0xbf00<<16);        \
        write_code( ((uint32_t)(x)&~3)  , align);           \
        write_code( ((uint32_t)(x)&~3)+4, 0xf000f8df);      \
        write_code( ((uint32_t)(x)&~3)+8, func);            \
    }                                                       \
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

    //aligned jump
    if (~x & 0x2) {
        write_code( (x&~3)  , 0xf000f8df);
        write_code( (x&~3)+4, ((uint32_t)hook) | 1);

    //misaligned jump
    } else {
        uint32_t align = *(uint32_t*)((uint32_t)(x)&~3);
        align = (align & 0x0000ffff) | (0xbf00<<16);
        write_code( (x&~3)  , align);
        write_code( (x&~3)+4, 0xf000f8df);
        write_code( (x&~3)+8, ((uint32_t)hook) | 1);
    }
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
struct hook *add_hook(void *target, void (*pre_hook)(struct saved_regs* regs, void *arg), uint32_t (*post_hook)(uint32_t retval, void *arg), void *arg) {
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
    #define trace(func, n, hasret) add_hook(&func, &trace_prehook_##n, &trace_posthook_##hasret, #func);

    //XXX 0x201cec is the current thread ptr, make generic
    #define trace_color "\033[;36m"
    void trace_prehook_0(struct saved_regs *regs, void *func_name) {  \
        print(trace_color);
        //print("thrd=");
        //print_ptr(_tx_thread_current_ptr);
        print("lr=");
        print_ptr(regs->lr);
        print(" ");
        puts(func_name);
        print("(");
        print(")\033[;00m");
    }

    void trace_prehook_1(struct saved_regs *regs, void *func_name) {  \
        print(trace_color);
        //print("thrd=");
        //print_ptr(_tx_thread_current_ptr);
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
        //print("thrd=");
        //print_ptr(_tx_thread_current_ptr);
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
        //print("thrd=");
        //print_ptr(_tx_thread_current_ptr);
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
        //print("thrd=");
        //print_ptr(_tx_thread_current_ptr);
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

#endif
#endif

#endif
