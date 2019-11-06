
INCLUDE gen/symbols.ld;
ENTRY(_start);
SECTIONS {
    . = 0x20a000;
    .text : { *(.text) }
    .data : { *(.data) }
    .bss : { *(.bss) }
}
