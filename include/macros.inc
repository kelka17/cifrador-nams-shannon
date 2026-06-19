; include/macros.inc
; Macros compartidas para mantener el codigo NASM legible.

%ifndef MACROS_INC
%define MACROS_INC

%macro EXIT 1
    mov rdi, %1
    call sys_exit
%endmacro

%macro WRITE 3
    mov rdi, %1
    mov rsi, %2
    mov rdx, %3
    call sys_write
%endmacro

%endif
