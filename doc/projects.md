To work on your own, you first have to create a project in the WebUI.
Then you can set up the environment, by either loading an ELF binary, or raw binary dumps.
If you loaded an ELF file, symbols are extracted automatically.
Or you can run:

```
python3 cli.py project -p [Project Name] -c -e [ELF File]
```

After this, you will have a directory `projects/[Project Name]` where all your files will live.

Table of Contents
------------
- [Write a Hello World](#hello-world)
- [Trace functions](#trace-functions)
- [Remove functions](#removing-functions)
- [Replace functions](#replacing-functions)
- [Hook functions](#hooking-functions)

# Hello World

To run code within the firmware, you have to create a C file within the directory `emulation/` in your project directory.
A simple hello world looks like this.

```C
#include <frankenstein.h>

int _start() {
    print("Hello\\o/\n");
    /* Your code goes here */
}
```

In this environment, you have the address space available, that you have set up earlier.
Here you can use symbols, that are imported into the project.
To access them in C you have first to declare them, so the compiler knows the signature.


# Patching the firmware

In most cases, we need to modify the code to execute it.
For this purpose some functions are provided, that can be used to patch the code.
Those functions do not require the symbol to be declared in the first place.
They are using a macro like the following to obtain the address using assembly.

```C
#define get_symbol_address(func, addr)          \
     asm("ldr %0, ="#func"\n": "=r" (addr));

```

## Trace Functions

Tracing functions can be useful to analyze function calls.
This uses our [hooking](#hooking-functions) method described later.

```C
trace(function_name, n_args, hasret);
```
`n_args` is the number of arguments, that are passed to that function.
`hasret` can be either `true` or `false` and is used to show the return value of that function.
As soon the target function is executed a debug message is printed, that looks like the following:

```
target_function(0xc0ffe)[Output within target_function] = 0xbeef;
```

## Removing functions

Some functions, that use unsupported instructions or cause an endless loop might have to be disabled.
In that case, we can overwrite the function with a plain return.
This will not modify the `r0` register.

```C
patch_return(function_name);
```

Architecture | Instruction  | Size
-------------|--------------|------
Arm Thumb    | `bx lr`      | 2
Arm          | `bx lr`      | 4


## Replacing Functions

Other functions need to be replaced with your function.
This will overwrite the function prologue with an unconditional jump.
The jump is absolute, as our code lives at a high address, that is not reachable with a relative jump

```C
patch_jump(src, dst);
```

Architecture | Instruction  | Size
-------------|--------------|------
Arm Thumb (aligned function)        | `ldr pc, {pc}; .word target`          | 8
Arm Thumb (misaligned function)     | `nop; ldr pc, {pc}; .word target`     | 10
Arm                                 | `dr pc, [pc, #-4]; .word target`      | 8

## Hooking Functions

This hooking mechanism is used, if the original function has to be executed as well.
It will save the original 12 bytes of the function prologue and then use [patch_jump()](#replacing-functions) method described earlier.
As the target function is called, a wrapper is executed, that will restore the function prologue and execute the supplied `pre_hook` function.
Furthermore, the link register (`lr`) is set to jump to a pos hook logic, that is executed, as the function returns.
This will execute `post_hook` and re-install the hook.


```C
void post_hook(struct saved_regs* regs, void *arg);
vint32_t (*post_hook)(uint32_t retval, void *arg), void *arg);
void *arg;

add_hook(target, pre_hook, post_hook, arg);
```

# Misc Functions

The current state of the project does not allow us to use the libc.
There would be a multitude of collisions with symbols, and the linking process is quite complex.
Also, it is not available on the target device.
Therefore we provide a minmal subset of functions that can be found in [utils.h](../include/frankenstein/utils.h) .
The most important are:

```C
print("some constant");         //Prints a constant string
print_ptr(void *)               //Something like %p
print_var(some_int)             //Will print some_int=0xc0ffee
hexdump(char *, size_t)         //Prints a hexdump of a buffer
```



# Project structure

Project directories have the following structure:

- **project.json**
A file containing all data about the project, including symbols and memory layout. The structure is described below.

- **segment_groups**
One firmware dump contains of multiple memory segments, such as RAM, ROM etc.
Segments (continuous memory regions) are organized in groups.
Each group is one complete firmware image and can be managed separately.


- **patches/**
It contains multiple C files that are compiled to a .patch file.
Those are compiled to a contiguous memory chunk located at PATCH_CODE_BASE.

- **emulation/**
Firmware emulator files compiled to .exe files.


- **include/**
Holds project specific header files.

- **gen/**


## project.json Structure

The file `project.json` holds all information about the project, except the actual binary dumps.
From this method, the build scripts are generated.

```
config
    TOOLCHAIN
    EMULATION_CFLAGS
    EMULATION_CODE_BASE
    PATCH_CODE_BASE
    PATCH_CFLAGS

segment_groups{}
    key: name
    active
    symbols {}
        key: name
        addr
    segments{}
        key: name
        addr
        size
        active

symbols{}
    key: name
    addr
```
