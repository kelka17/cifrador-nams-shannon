; =============================================================================
; test_entropy.asm — Tests de regresión para entropy.asm
; =============================================================================
;
; Compila y enlaza:
;   nasm -f elf64 -Iinclude/ -o test_entropy.o test_entropy.asm
;   nasm -f elf64 -Iinclude/ -o entropy.o      entropy.asm
;   nasm -f elf64 -Iinclude/ -o io.o           io.asm
;   nasm -f elf64 -Iinclude/ -o display.o      display.asm
;   ld -o test_entropy test_entropy.o entropy.o io.o display.o
; Ejecuta:
;   ./test_entropy ; echo $?   (debe ser 0)
;
; =============================================================================
;
; VALORES ESPERADOS (calculados analíticamente, verificados con FPU x87):
;
; ── TEST 1 — frequency_clear ─────────────────────────────────────────────────
;   Postcondición: ∀ i ∈ [0,255]: frequency_table[i] = 0.
;   Se verifican los índices 0x00, 0x7F y 0xFF (primero, medio, último).
;
; ── TEST 2 — frequency_count("AABBC", 5) ─────────────────────────────────────
;   Buffer: [0x41='A', 0x41='A', 0x42='B', 0x42='B', 0x43='C']
;   Resultado esperado:
;     frequency_table[0x41] = 2  (A aparece 2 veces)
;     frequency_table[0x42] = 2  (B aparece 2 veces)
;     frequency_table[0x43] = 1  (C aparece 1 vez)
;     frequency_table[0x44] = 0  (D no aparece: sentinela de no-contaminación)
;
; =============================================================================

%include "include/syscalls.inc"

global _start

extern sys_exit
extern io_print_string, io_print_newline, io_print_uint64
extern frequency_clear, frequency_count
extern frequency_table

; =============================================================================
section .rodata
; =============================================================================

    ansi_green   db 27, "[32m", 0
    ansi_red     db 27, "[31m", 0
    ansi_cyan    db 27, "[36m", 0
    ansi_reset   db 27, "[0m",  0

    msg_ok       db " [OK]",   10, 0
    msg_fail     db " [FAIL]", 10, 0

    ; ── cabeceras de sección ─────────────────────────────────────────────────
    hdr_clear    db "=== TEST 1: frequency_clear — tabla de frecuencias a cero ===", 0
    hdr_count    db "=== TEST 2: frequency_count('AABBC', 5) ===", 0
    hdr_done     db "=== TODOS LOS TESTS PASARON ===", 0

    ; ── etiquetas de items ───────────────────────────────────────────────────
    lbl_freq0    db "  freq[0x00] -> ", 0
    lbl_freq7F   db "  freq[0x7F] -> ", 0
    lbl_freqFF   db "  freq[0xFF] -> ", 0
    lbl_freqA    db "  freq['A'=0x41] -> ", 0
    lbl_freqB    db "  freq['B'=0x42] -> ", 0
    lbl_freqC    db "  freq['C'=0x43] -> ", 0
    lbl_freqD    db "  freq['D'=0x44] -> ", 0

    ; ── datos de prueba ──────────────────────────────────────────────────────
    buf_AABBC    db 0x41, 0x41, 0x42, 0x42, 0x43   ; "AABBC" — 5 bytes

; =============================================================================
; MACROS
; =============================================================================

; SECTION_HDR msg — imprime encabezado de sección en cian
%macro SECTION_HDR 1
    call io_print_newline
    mov  rdi, ansi_cyan
    call io_print_string
    mov  rdi, %1
    call io_print_string
    mov  rdi, ansi_reset
    call io_print_string
    call io_print_newline
%endmacro

; OK_MSG — imprime " [OK]\n" en verde
%macro OK_MSG 0
    mov  rdi, ansi_green
    call io_print_string
    mov  rdi, msg_ok
    call io_print_string
    mov  rdi, ansi_reset
    call io_print_string
%endmacro

; FAIL_MSG — imprime " [FAIL]\n" en rojo
%macro FAIL_MSG 0
    mov  rdi, ansi_red
    call io_print_string
    mov  rdi, msg_fail
    call io_print_string
    mov  rdi, ansi_reset
    call io_print_string
%endmacro

; ASSERT_MEM64 base_reg, byte_index, expected_imm64
;   Lee [base_reg + byte_index * 8] y compara con expected.
;   Destruye rax, r11.
%macro ASSERT_MEM64 3
    mov  rax, [%1 + %2 * 8]
    mov  r11, %3
    cmp  rax, r11
    je   %%pass
    FAIL_MSG
    jmp  %%end
%%pass:
    OK_MSG
%%end:
%endmacro

; =============================================================================
section .text
; =============================================================================

_start:
    push r13                   ; callee-saved — base de frequency_table

; =============================================================================
; TEST 1 — frequency_clear: toda la tabla debe quedar en cero
; =============================================================================
    SECTION_HDR hdr_clear

    call frequency_clear

    ; cargar base de la tabla en r13 (callee-saved, sobrevive a los prints)
    lea  r13, [rel frequency_table]

    ; verificar freq[0x00] == 0
    mov  rdi, lbl_freq0
    call io_print_string
    ASSERT_MEM64 r13, 0x00, 0

    ; verificar freq[0x7F] == 0  (entrada central)
    mov  rdi, lbl_freq7F
    call io_print_string
    ASSERT_MEM64 r13, 0x7F, 0

    ; verificar freq[0xFF] == 0  (última entrada)
    mov  rdi, lbl_freqFF
    call io_print_string
    ASSERT_MEM64 r13, 0xFF, 0

; =============================================================================
; TEST 2 — frequency_count("AABBC", 5): conteos de bytes conocidos
; =============================================================================
    SECTION_HDR hdr_count

    ; la tabla ya fue limpiada en TEST 1; frequency_count acumula sobre ella
    mov  rdi, buf_AABBC
    mov  rsi, 5
    call frequency_count

    lea  r13, [rel frequency_table]   ; recargar base (frequency_count modifica rdi)

    ; freq['A'=0x41] == 2
    mov  rdi, lbl_freqA
    call io_print_string
    ASSERT_MEM64 r13, 0x41, 2

    ; freq['B'=0x42] == 2
    mov  rdi, lbl_freqB
    call io_print_string
    ASSERT_MEM64 r13, 0x42, 2

    ; freq['C'=0x43] == 1
    mov  rdi, lbl_freqC
    call io_print_string
    ASSERT_MEM64 r13, 0x43, 1

    ; freq['D'=0x44] == 0  (sentinela: ningún byte extra fue contaminado)
    mov  rdi, lbl_freqD
    call io_print_string
    ASSERT_MEM64 r13, 0x44, 0

; =============================================================================
; FIN
; =============================================================================
    call io_print_newline
    SECTION_HDR hdr_done

    pop  r13
    mov  rdi, 0
    call sys_exit
