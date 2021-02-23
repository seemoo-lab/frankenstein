EMULATION_CFLAGS=-c -static -fpic -pie -nostdlib -g -Ttext $(EMULATION_CODE_BASE) -I include -I gen -I ../../include  -I /usr/include -D FRANKENSTEIN_EMULATION
EMULATION_CODE_BASE=0xbeef000
PATCH_CFLAGS=-O2 -static -nostdlib -Tgen/patch.ld -mcpu=cortex-m4 -I include  -I ../../include
PATCH_CODE_BASE=0x271a00
TOOLCHAIN=arm-none-eabi-
thumb_mode=0x1

.PHONY=all

SEGMENTS_RAW=$(wildcard segment_groups/*/*.bin)
SEGMENTS_OBJ=$(patsubst segment_groups/%.bin, gen/%.segment.o, $(SEGMENTS_RAW))

SRC_EMU=$(wildcard emulation/*.c)
OBJ_EMU=$(patsubst emulation/%.c, gen/%.exe, $(SRC_EMU))

SRC_PATCH=$(wildcard patch/*.c)
OBJ_PATCH=$(patsubst patch/%.c, gen/%.patch, $(SRC_PATCH))


#make linkable object from memory dump
gen/%.segment.o : segment_groups/%.bin
	@mkdir $(shell dirname $@) 2>/dev/null || true
	$(TOOLCHAIN)ld -r -b binary -o $@ $^

#create executable
gen/%.exe : emulation/%.c
	$(TOOLCHAIN)gcc $(EMULATION_CFLAGS) -o gen/src.o $^
	$(TOOLCHAIN)ld -T gen/segments.ld -o $@  --no-warn-mismatch

#patches
gen/%.patch : patch/%.c
	$(TOOLCHAIN)gcc $(PATCH_CFLAGS) -o $@ $^

all: clean $(SEGMENTS_OBJ) $(OBJ_EMU) $(OBJ_PATCH)

clean:
	@echo clean
	@rm gen/src.o 2>/dev/null || true
	@rm $(SEGMENTS_OBJ) 2>/dev/null || true
	@rm $(OBJ_EMU) 2>/dev/null || true
	@rm $(OBJ_PATCH) 2>/dev/null || true
