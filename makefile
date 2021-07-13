BUILD:=./build
TESTS:=./tests

ASM=nasm
ASM_FLAGS:= -f elf32


$(BUILD)/%.o: $(TESTS)/%.asm
	$(ASM) $(ASM_FLAGS) $< -o $@

.PHONY:test
test: $(BUILD)/test.o
	-

.PHONY:main
main: $(BUILD)/test.o src/main.py
	@python src/main.py
