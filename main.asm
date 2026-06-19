; main.asm
; Punto de entrada del programa cifrador.
;
; Responsabilidad:
; - Validar argumentos CLI.
; - Coordinar lectura, cifrado/descifrado, entropia, cabecera y salida.
; - Terminar el proceso mediante sys_exit.

%include "include/syscalls.inc"
%include "include/macros.inc"
%include "include/header.inc"

global _start
extern sys_write
extern sys_exit

section .rodata
    banner db "================================", 10
           db " CIFRADOR NASM", 10
           db "================================", 10, 0
    banner_len equ $ - banner - 1

    usage db "Uso:", 10
          db "  ./cifrador encrypt entrada salida clave", 10
          db "  ./cifrador decrypt entrada salida clave", 10, 0
    usage_len equ $ - usage - 1

section .text
_start:
    ; En Linux x86-64, al entrar por _start:
    ; [rsp]     = argc
    ; [rsp + 8] = argv[0]
    ; [rsp+16]  = argv[1]
    mov rdi, STDOUT
    mov rsi, banner
    mov rdx, banner_len
    call sys_write

    mov rax, [rsp]
    cmp rax, 5
    je .ok_args

    mov rdi, STDOUT
    mov rsi, usage
    mov rdx, usage_len
    call sys_write

    mov rdi, 1
    call sys_exit

.ok_args:
    ; Estructura lista. En el siguiente paso se conectan:
    ; argv[1] modo, argv[2] entrada, argv[3] salida, argv[4] clave.
    mov rdi, 0
    call sys_exit
