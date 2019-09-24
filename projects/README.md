## File Structure
Project directories have the following structure:

- **project.json**
File containing all data about the project, including symbols and memory layout. The structure is described below.

- **segment_groups**
One firmware dump contains of multiple memory segments, such as RAM, ROM etc.
Segments (continuous memory regions) are organized in groups.
Each group is one complete firmware image and can be managed separately.


- **patches/**
Contains multiple C files that are compiled to an .patch file.
Those are compiled to a continuous memory chunk located at PATCH_CODE_BASE.

- **emulation/**
Firmware emulator files compiled to .exe files.


- **include/**
Holds project specific header files.

- **gen/**


## project.json file structure
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

