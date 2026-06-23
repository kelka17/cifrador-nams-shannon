NASM := nasm
LD := ld

TARGET := cifrador
ASM := main.asm io.asm cipher.asm transpose.asm entropy.asm header.asm display.asm
OBJ := $(ASM:.asm=.o)

NASMFLAGS := -f elf64 -Iinclude/
LDFLAGS :=

.PHONY: all run clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(LD) $(LDFLAGS) -o $@ $^

%.o: %.asm include/syscalls.inc include/macros.inc include/header.inc
	$(NASM) $(NASMFLAGS) -o $@ $<

run: $(TARGET)
	./$(TARGET)

test_header: test_header.o header.o io.o cipher.o transpose.o
	$(LD) -o $@ $^

test_header.o: test_header.asm include/syscalls.inc include/header.inc
	$(NASM) $(NASMFLAGS) -o $@ $<

clean:
	rm -f $(OBJ) $(TARGET) test_header test_header.o
