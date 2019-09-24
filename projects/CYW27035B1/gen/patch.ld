
INCLUDE gen/symbols.ld;
ENTRY(_start);
SECTIONS {
    . = 0x271a00;
    .text : { *(.text) }
    .data : { *(.data) }
    .bss : { *(.bss) }
}
