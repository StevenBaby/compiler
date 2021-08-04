BUILD:=./build
TESTS:=./tests

ASM=nasm
ASM_FLAGS:= -f elf32
LD=ld
LDFLAGS:= -m elf_i386 -static -e main
CC:=gcc
CFLAGS:= -m32

$(BUILD)/%.o: $(TESTS)/%.asm
	$(ASM) $(ASM_FLAGS) $< -o $@

$(BUILD)/%: $(BUILD)/%.o
	$(LD) $(LDFLAGS) $< -o $@

$(BUILD)/test.so: $(TESTS)/test.c
	$(CC) $(CFLAGS) $< -o $@

.PHONY:main
main: $(BUILD)/test.o src/main.py
	@python src/main.py
