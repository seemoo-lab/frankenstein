INCLUDE gen/symbols.ld;
ENTRY(_start);
MEMORY {
}
SECTIONS {
  .src.bss 0xbeee000:{ gen/src.o (.bss)}
  .src 0xbeef000:{ gen/src.o (*)}
}
