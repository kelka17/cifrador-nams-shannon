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

test_entropy: test_entropy.o entropy.o io.o display.o
	$(LD) -o $@ $^

test_entropy.o: test_entropy.asm include/syscalls.inc
	$(NASM) $(NASMFLAGS) -o $@ $<

clean:
	rm -f $(OBJ) $(TARGET) test_entropy test_entropy.o
