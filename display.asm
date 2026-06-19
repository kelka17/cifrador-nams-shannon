; display.asm
; Salida en consola, mensajes, colores ANSI e histogramas ASCII.

%include "include/syscalls.inc"

global display_histogram
global display_error
extern sys_write

section .text

; void display_histogram(uint64_t *frequency_table, uint64_t total)
display_histogram:
    ret

; void display_error(const char *message, uint64_t length)
display_error:
    mov rdx, rsi
    mov rsi, rdi
    mov rdi, STDERR
    call sys_write
    ret
