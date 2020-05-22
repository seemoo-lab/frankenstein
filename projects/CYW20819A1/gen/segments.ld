INCLUDE gen/symbols.ld;
ENTRY(_start);
MEMORY {
  Segment_0x0 (rwx)  : ORIGIN = 0x0, LENGTH = 0x280000
  Segment_0x300000 (rwx)  : ORIGIN = 0x300000, LENGTH = 0x8000
  Segment_0x310000 (rwx)  : ORIGIN = 0x310000, LENGTH = 0x12000
  Segment_0x326000 (rwx)  : ORIGIN = 0x326000, LENGTH = 0xa000
  Segment_0x338000 (rwx)  : ORIGIN = 0x338000, LENGTH = 0x8000
  Segment_0x341000 (rwx)  : ORIGIN = 0x341000, LENGTH = 0x1000
  Segment_0x350000 (rwx)  : ORIGIN = 0x350000, LENGTH = 0x18000
  Segment_0x370000 (rwx)  : ORIGIN = 0x370000, LENGTH = 0x10000
  Segment_0x390000 (rwx)  : ORIGIN = 0x390000, LENGTH = 0x8000
  Segment_0x404000 (rwx)  : ORIGIN = 0x404000, LENGTH = 0x4000
  Segment_0x410000 (rwx)  : ORIGIN = 0x410000, LENGTH = 0x4000
  Segment_0x420000 (rwx)  : ORIGIN = 0x420000, LENGTH = 0x4000
  Segment_0x430000 (rwx)  : ORIGIN = 0x430000, LENGTH = 0x4000
  Segment_0x440000 (rwx)  : ORIGIN = 0x440000, LENGTH = 0x4000
  Segment_0x450000 (rwx)  : ORIGIN = 0x450000, LENGTH = 0x4000
  Segment_0x500000 (rwx)  : ORIGIN = 0x500000, LENGTH = 0x41000
  Segment_0x580000 (rwx)  : ORIGIN = 0x580000, LENGTH = 0x80800
  Segment_0x640000 (rwx)  : ORIGIN = 0x640000, LENGTH = 0x800
  Segment_0x650000 (rwx)  : ORIGIN = 0x650000, LENGTH = 0x1000
  Segment_0xe0000000 (rwx)  : ORIGIN = 0xe0000000, LENGTH = 0x100000
}
SECTIONS {
  .Segment_0x0 0x0:{ gen/default/Segment_0x0.segment.o} > Segment_0x0
  .Segment_0x300000 0x300000:{ gen/default/Segment_0x300000.segment.o} > Segment_0x300000
  .Segment_0x310000 0x310000:{ gen/default/Segment_0x310000.segment.o} > Segment_0x310000
  .Segment_0x326000 0x326000:{ gen/default/Segment_0x326000.segment.o} > Segment_0x326000
  .Segment_0x338000 0x338000:{ gen/default/Segment_0x338000.segment.o} > Segment_0x338000
  .Segment_0x341000 0x341000:{ gen/default/Segment_0x341000.segment.o} > Segment_0x341000
  .Segment_0x350000 0x350000:{ gen/default/Segment_0x350000.segment.o} > Segment_0x350000
  .Segment_0x370000 0x370000:{ gen/default/Segment_0x370000.segment.o} > Segment_0x370000
  .Segment_0x390000 0x390000:{ gen/default/Segment_0x390000.segment.o} > Segment_0x390000
  .Segment_0x404000 0x404000:{ gen/default/Segment_0x404000.segment.o} > Segment_0x404000
  .Segment_0x410000 0x410000:{ gen/default/Segment_0x410000.segment.o} > Segment_0x410000
  .Segment_0x420000 0x420000:{ gen/default/Segment_0x420000.segment.o} > Segment_0x420000
  .Segment_0x430000 0x430000:{ gen/default/Segment_0x430000.segment.o} > Segment_0x430000
  .Segment_0x440000 0x440000:{ gen/default/Segment_0x440000.segment.o} > Segment_0x440000
  .Segment_0x450000 0x450000:{ gen/default/Segment_0x450000.segment.o} > Segment_0x450000
  .Segment_0x500000 0x500000:{ gen/default/Segment_0x500000.segment.o} > Segment_0x500000
  .Segment_0x580000 0x580000:{ gen/default/Segment_0x580000.segment.o} > Segment_0x580000
  .Segment_0x640000 0x640000:{ gen/default/Segment_0x640000.segment.o} > Segment_0x640000
  .Segment_0x650000 0x650000:{ gen/default/Segment_0x650000.segment.o} > Segment_0x650000
  .Segment_0xe0000000 0xe0000000:{ gen/default/Segment_0xe0000000.segment.o} > Segment_0xe0000000
  .src 0xbeef000:{ gen/src.o (.text)}
  .bss 0xb4ef000:{ gen/src.o (*)}
}
