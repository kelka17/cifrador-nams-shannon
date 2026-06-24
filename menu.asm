; =============================================================================
; Archivo:     menu.asm
; Proyecto:    Cifrador/Descifrador con Análisis de Entropía de Shannon
; Asignatura:  Taller de Programación en Bajo Nivel
; Universidad: UMSS — Facultad de Ciencias y Tecnología
; Descripción: Menú interactivo: display, lectura de opción y contraseña.
; =============================================================================
;
; FUNCIONES EXPORTADAS:
;   menu_display_main()            — imprime el menú principal
;   menu_read_choice() → rax       — lee opción válida '0'-'4', retorna 0-4
;   menu_get_password(buf, maxlen) — lee contraseña sin eco, null-termina buf
;   menu_display_info()            — panel de información del proyecto
;
; CONVENCIÓN: System V AMD64 ABI
; =============================================================================

%include "include/syscalls.inc"

global menu_display_main
global menu_read_choice
global menu_get_password
global menu_display_info

extern io_print_string
extern io_read_line
extern io_set_no_echo
extern io_set_echo

; =============================================================================
section .rodata
; =============================================================================

    ANSI_RESET  db 0x1B, "[0m", 0
    ANSI_BOLD   db 0x1B, "[1m", 0
    ANSI_CYAN   db 0x1B, "[36m", 0
    ANSI_YELLOW db 0x1B, "[33m", 0
    ANSI_GREEN  db 0x1B, "[32m", 0
    ANSI_RED    db 0x1B, "[31m", 0

    ; ── Menú principal ───────────────────────────────────────────────────────
    menu_box db 10
             db 0x1B, "[1m", 0x1B, "[36m"
             db "  +========================================================+", 10
             db "  |          CIFRADOR NASM v1.0  --  MENU PRINCIPAL        |", 10
             db "  |      Criptografia + Entropia de Shannon (FPU x87)      |", 10
             db "  +========================================================+", 10
             db 0x1B, "[0m"
             db 0x1B, "[1m"
             db "  |                                                        |", 10
             db "  |   1.  Cifrar archivo                                   |", 10
             db "  |   2.  Descifrar archivo                                |", 10
             db "  |   3.  Analizar entropia de archivo                     |", 10
             db "  |   4.  Informacion del proyecto                         |", 10
             db "  |   0.  Salir                                            |", 10
             db "  |                                                        |", 10
             db "  +========================================================+", 10
             db 0x1B, "[0m", 10, 0

    menu_prompt  db "  Opcion (0-4): ", 0
    menu_err_opt db 0x1B, "[31m", "  Opcion invalida. Ingrese un numero del 0 al 4.", 0x1B, "[0m", 10, 0

    ; ── Panel de información ─────────────────────────────────────────────────
    info_box db 10
             db 0x1B, "[1m", 0x1B, "[36m"
             db "  +========================================================+", 10
             db "  |              INFORMACION DEL PROYECTO                  |", 10
             db "  +========================================================+", 10
             db 0x1B, "[0m"
             db "  |  Nombre:      Cifrador/Descifrador NASM                |", 10
             db "  |  Version:     1.0                                      |", 10
             db "  |  Plataforma:  Linux x86-64 (sin libc)                  |", 10
             db "  |  Arquitectura:System V AMD64 ABI                       |", 10
             db "  |                                                        |", 10
             db "  |  Modulos (9):                                          |", 10
             db "  |    main.asm  io.asm  cipher.asm  transpose.asm         |", 10
             db "  |    entropy.asm  header.asm  display.asm                |", 10
             db "  |    report.asm  log.asm  menu.asm                       |", 10
             db "  |                                                        |", 10
             db "  |  Algoritmos:                                           |", 10
             db "  |    Cifrado : XOR stream 64-bit + BSWAP transposition   |", 10
             db "  |    Entropia: Shannon H(X) via FPU x87 (FYL2X)         |", 10
             db "  |    Cabecera: CRYP magic + checksum aritmetico mod 2^32 |", 10
             db "  |                                                        |", 10
             db "  |  Asignatura: Taller de Programacion en Bajo Nivel      |", 10
             db "  |  Universidad: UMSS -- Facultad de Ciencias y Tec.      |", 10
             db "  +========================================================+", 10
             db 0x1B, "[0m", 10, 0

    pass_echo_off db 10, 0       ; newline antes de leer (queda en misma línea)

; =============================================================================
section .bss
; =============================================================================

    choice_buf  resb 8           ; buffer para leer la opción del menú

; =============================================================================
section .text
; =============================================================================

; =============================================================================
; menu_display_main — imprime el menú principal
; =============================================================================
; void menu_display_main(void)
menu_display_main:
    lea  rdi, [rel menu_box]
    call io_print_string
    ret

; =============================================================================
; menu_read_choice — lee una opción válida del teclado
; =============================================================================
; int menu_read_choice(void)
;   rax = opción seleccionada (0-4)
;
; TABLA DE REGISTROS:
;   rbx = base del choice_buf (callee-saved)
menu_read_choice:
    push rbx
    lea  rbx, [rel choice_buf]

.mrc_loop:
    lea  rdi, [rel menu_prompt]
    call io_print_string

    mov  rdi, rbx                ; buffer
    mov  rsi, 4                  ; max 4 bytes (evitar overrun)
    call io_read_line            ; rax = bytes leídos

    test rax, rax
    jz   .mrc_invalid            ; línea vacía → inválida

    movzx rax, byte [rbx]        ; primer carácter
    sub  rax, '0'                ; convertir a entero
    js   .mrc_invalid            ; < '0'
    cmp  rax, 4
    jg   .mrc_invalid            ; > '4'

    pop  rbx
    ret                          ; rax = opción válida 0-4

.mrc_invalid:
    lea  rdi, [rel menu_err_opt]
    call io_print_string
    jmp  .mrc_loop

; =============================================================================
; menu_get_password — lee contraseña sin mostrar caracteres en pantalla
; =============================================================================
; void menu_get_password(char *buf, uint64_t max_len)
;   rdi = buffer destino
;   rsi = tamaño máximo (incluyendo null)
;
; TABLA DE REGISTROS:
;   rbx = buffer (callee-saved)
;   r12 = max_len (callee-saved)
menu_get_password:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12, rsi

    call io_set_no_echo          ; desactivar eco

    mov  rdi, rbx                ; buffer
    mov  rsi, r12                ; max_len
    call io_read_line            ; lee sin mostrar caracteres

    call io_set_echo             ; restaurar eco (también imprime \n)

    pop  r12
    pop  rbx
    ret

; =============================================================================
; menu_display_info — muestra el panel de información del proyecto
; =============================================================================
; void menu_display_info(void)
menu_display_info:
    lea  rdi, [rel info_box]
    call io_print_string
    ret
