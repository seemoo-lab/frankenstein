INCLUDE gen/symbols.ld;
ENTRY(_start);
MEMORY {
  Segment_0x0 (rwx)  : ORIGIN = 0x0, LENGTH = 0x400000
}
SECTIONS {
  .Segment_0x0 0x0:{ gen/default/Segment_0x0.segment.o} > Segment_0x0
  .src.bss 0xbeee000:{ gen/src.o (.bss)}
  .src 0xbeef000:{ gen/src.o (*)}
}
