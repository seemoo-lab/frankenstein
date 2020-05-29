INCLUDE gen/symbols.ld;
ENTRY(_start);
MEMORY {
  Segment_0x0 (rwx)  : ORIGIN = 0x0, LENGTH = 0x140000
  Segment_0x160000 (rwx)  : ORIGIN = 0x160000, LENGTH = 0x20000
  Segment_0x200000 (rwx)  : ORIGIN = 0x200000, LENGTH = 0x88000
  Segment_0x300000 (rwx)  : ORIGIN = 0x300000, LENGTH = 0x8000
  Segment_0x310000 (rwx)  : ORIGIN = 0x310000, LENGTH = 0x12000
  Segment_0x324000 (rwx)  : ORIGIN = 0x324000, LENGTH = 0x44000
  Segment_0x370000 (rwx)  : ORIGIN = 0x370000, LENGTH = 0x10000
  Segment_0x390000 (rwx)  : ORIGIN = 0x390000, LENGTH = 0x8000
  Segment_0x500000 (rwx)  : ORIGIN = 0x500000, LENGTH = 0x101000
  Segment_0x604800 (rwx)  : ORIGIN = 0x604800, LENGTH = 0x800
  Segment_0x640000 (rwx)  : ORIGIN = 0x640000, LENGTH = 0x1000
  Segment_0x650000 (rwx)  : ORIGIN = 0x650000, LENGTH = 0x100
  Segment_0xe0000000 (rwx)  : ORIGIN = 0xe0000000, LENGTH = 0x100000
}
SECTIONS {
  .Segment_0x0 0x0:{ gen/default/Segment_0x0.segment.o} > Segment_0x0
  .Segment_0x160000 0x160000:{ gen/default/Segment_0x160000.segment.o} > Segment_0x160000
  .Segment_0x200000 0x200000:{ gen/default/Segment_0x200000.segment.o} > Segment_0x200000
  .Segment_0x300000 0x300000:{ gen/default/Segment_0x300000.segment.o} > Segment_0x300000
  .Segment_0x310000 0x310000:{ gen/default/Segment_0x310000.segment.o} > Segment_0x310000
  .Segment_0x324000 0x324000:{ gen/default/Segment_0x324000.segment.o} > Segment_0x324000
  .Segment_0x370000 0x370000:{ gen/default/Segment_0x370000.segment.o} > Segment_0x370000
  .Segment_0x390000 0x390000:{ gen/default/Segment_0x390000.segment.o} > Segment_0x390000
  .Segment_0x500000 0x500000:{ gen/default/Segment_0x500000.segment.o} > Segment_0x500000
  .Segment_0x604800 0x604800:{ gen/default/Segment_0x604800.segment.o} > Segment_0x604800
  .Segment_0x640000 0x640000:{ gen/default/Segment_0x640000.segment.o} > Segment_0x640000
  .Segment_0x650000 0x650000:{ gen/default/Segment_0x650000.segment.o} > Segment_0x650000
  .Segment_0xe0000000 0xe0000000:{ gen/default/Segment_0xe0000000.segment.o} > Segment_0xe0000000
  .text 0xbeef000:{ gen/src.o (.text)}
  .data ALIGN(LOADADDR(.text)+SIZEOF(.text), 0x1000):{ * (*)}
}
