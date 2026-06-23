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
; ── TEST 3 — entropy_calculate, H = 0 bits/byte ──────────────────────────────
;   Buffer: [0x41, 0x41, 0x41, 0x41] (4 bytes, símbolo único 'A')
;   Distribución: p₀x₄₁ = 4/4 = 1.0, todos los demás = 0
;   Secuencia FPU para p=1.0:
;     FILD freq=4  → ST0=4.0
;     FILD total=4 → ST0=4.0, ST1=4.0
;     FDIVP        → ST0=4/4=1.0    [p = 1.0]
;     FLD ST0      → ST0=1.0, ST1=1.0
;     FYL2X        → ST0=1.0·log₂(1.0)=1.0·0.0=0.0
;     FCHS         → ST0=-0.0=0.0
;     FADDP        → ST0=H_acc+0.0=0.0
;   H = 0.0 bits/byte     → millis = 0
;
; ── TEST 4 — entropy_calculate, H = 1 bit/byte ───────────────────────────────
;   Buffer: [0x41, 0x42] (2 bytes, 'A' y 'B' con p=½ c/u)
;   Secuencia FPU para p=0.5 (cada símbolo):
;     FDIVP → ST0=1/2=0.5       [p = 0.5]
;     FYL2X → ST0=0.5·log₂(0.5)=0.5·(−1.0)=−0.5
;     FCHS  → ST0=+0.5
;   H = 0.5 + 0.5 = 1.0 bits/byte  → millis = 1000
;
; ── TEST 5 — entropy_calculate, H = 3 bits/byte ──────────────────────────────
;   Buffer: "ABCDEFGH" (8 bytes, 8 símbolos distintos con p=⅛ c/u)
;   Secuencia FPU para p=1/8:
;     FDIVP → ST0=1/8=0.125
;     FYL2X → ST0=0.125·log₂(0.125)=0.125·(−3.0)=−0.375  [log₂(2⁻³)=−3 exacto]
;     FCHS  → ST0=+0.375
;   H = 8 × 0.375 = 3.0 bits/byte  → millis = 3000
;
; ── TEST 6 — entropy_calculate, H = 8 bits/byte (máximo teórico) ─────────────
;   Tabla: frequency_table[i] = 1 ∀ i ∈ [0,255], total = 256
;   Secuencia FPU para p=1/256=2⁻⁸:
;     FDIVP → ST0=2⁻⁸
;     FYL2X → ST0=2⁻⁸·log₂(2⁻⁸)=2⁻⁸·(−8)=−1/32  [log₂(2⁻⁸)=−8 exacto]
;     FCHS  → ST0=+1/32
;   H = 256 × (1/32) = 8.0 bits/byte (máximo posible) → millis = 8000
;
; =============================================================================

%include "include/syscalls.inc"

global _start

extern sys_exit
extern io_print_string, io_print_newline, io_print_uint64
extern frequency_clear, frequency_count, entropy_calculate
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
    hdr_h0       db "=== TEST 3: entropy_calculate — H = 0.000 bits/byte (mono-simbolo) ===", 0
    hdr_h1       db "=== TEST 4: entropy_calculate — H = 1.000 bits/byte (dos simbolos p=1/2) ===", 0
    hdr_h3       db "=== TEST 5: entropy_calculate — H = 3.000 bits/byte (8 simbolos p=1/8) ===", 0
    hdr_h8       db "=== TEST 6: entropy_calculate — H = 8.000 bits/byte (256 simbolos, maximo) ===", 0
    hdr_done     db "=== TODOS LOS TESTS PASARON ===", 0

    ; ── etiquetas de items ───────────────────────────────────────────────────
    lbl_freq0    db "  freq[0x00] -> ", 0
    lbl_freq7F   db "  freq[0x7F] -> ", 0
    lbl_freqFF   db "  freq[0xFF] -> ", 0
    lbl_freqA    db "  freq['A'=0x41] -> ", 0
    lbl_freqB    db "  freq['B'=0x42] -> ", 0
    lbl_freqC    db "  freq['C'=0x43] -> ", 0
    lbl_freqD    db "  freq['D'=0x44] -> ", 0
    lbl_milli    db "  H x1000 = ", 0
    lbl_exp      db "  esperado = ", 0
    lbl_cmp      db "  resultado   ", 0

    ; ── datos de prueba ──────────────────────────────────────────────────────
    buf_AABBC    db 0x41, 0x41, 0x42, 0x42, 0x43   ; "AABBC" — 5 bytes
    buf_AAAA     db 0x41, 0x41, 0x41, 0x41          ; 4 × 'A'  (mono-símbolo)
    buf_AB       db 0x41, 0x42                       ; 'A', 'B' (equiprobables)
    buf_ABCDEFGH db "ABCDEFGH"                       ; 8 símbolos distintos

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

; ASSERT_EQ64 got_reg, expected_imm64
;   Compara got_reg con expected; imprime OK o FAIL.
;   Usa r11 como scratch (caller-saved).
%macro ASSERT_EQ64 2
    mov  r11, %2
    cmp  %1, r11
    je   %%pass
    FAIL_MSG
    jmp  %%end
%%pass:
    OK_MSG
%%end:
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

; ST0_TO_MILLI result_reg
;   Convierte ST0 (H en FPU x87) a millis enteros (H × 1000 → int64).
;   Guarda el resultado en result_reg (debe ser callee-saved: r12/r13/rbx).
;   Consume ST0; la pila FPU queda vacía.
%macro ST0_TO_MILLI 1
    sub  rsp, 8
    mov  qword [rsp], 1000
    fild qword [rsp]          ; ST0=1000.0, ST1=H
    fmulp st1, st0            ; ST1 = H × 1000, pop → ST0 = H × 1000
    fistp qword [rsp]         ; redondear a int64 y pop FPU
    pop  %1                   ; %1 = millis
%endmacro

; =============================================================================
section .text
; =============================================================================

_start:
    push rbx                   ; callee-saved — usado en fill loop TEST 6
    push r12                   ; callee-saved — millis resultado
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
; TEST 3 — entropy_calculate: H = 0 (todos los bytes son 'A')
; =============================================================================
    SECTION_HDR hdr_h0

    call frequency_clear
    mov  rdi, buf_AAAA
    mov  rsi, 4
    call frequency_count

    mov  rdi, 4
    call entropy_calculate       ; ST0 = H = 0.0
                                 ; (p₀x₄₁=1.0 → FYL2X(1.0,1.0)=1·log₂1=0)

    ST0_TO_MILLI r12             ; r12 = 0 × 1000 = 0

    mov  rdi, lbl_milli
    call io_print_string
    mov  rdi, r12
    call io_print_uint64
    call io_print_newline

    mov  rdi, lbl_exp
    call io_print_string
    mov  rdi, 0
    call io_print_uint64
    call io_print_newline

    mov  rdi, lbl_cmp
    call io_print_string
    ASSERT_EQ64 r12, 0

; =============================================================================
; TEST 4 — entropy_calculate: H = 1 (dos símbolos equiprobables, p = ½)
; =============================================================================
    SECTION_HDR hdr_h1

    call frequency_clear
    mov  rdi, buf_AB
    mov  rsi, 2
    call frequency_count

    mov  rdi, 2
    call entropy_calculate       ; ST0 = H = 1.0
                                 ; (p=½ → FYL2X(½,½)=½·log₂½=½·(−1)=−0.5 → FCHS=+0.5 × 2 = 1.0)

    ST0_TO_MILLI r12             ; r12 = 1.0 × 1000 = 1000

    mov  rdi, lbl_milli
    call io_print_string
    mov  rdi, r12
    call io_print_uint64
    call io_print_newline

    mov  rdi, lbl_exp
    call io_print_string
    mov  rdi, 1000
    call io_print_uint64
    call io_print_newline

    mov  rdi, lbl_cmp
    call io_print_string
    ASSERT_EQ64 r12, 1000

; =============================================================================
; TEST 5 — entropy_calculate: H = 3 (8 símbolos, p = ⅛ cada uno)
; =============================================================================
    SECTION_HDR hdr_h3

    call frequency_clear
    mov  rdi, buf_ABCDEFGH
    mov  rsi, 8
    call frequency_count

    mov  rdi, 8
    call entropy_calculate       ; ST0 = H = 3.0
                                 ; (log₂(1/8)=−3 exacto → 8×(1/8×3)=3)

    ST0_TO_MILLI r12             ; r12 = 3000

    mov  rdi, lbl_milli
    call io_print_string
    mov  rdi, r12
    call io_print_uint64
    call io_print_newline

    mov  rdi, lbl_exp
    call io_print_string
    mov  rdi, 3000
    call io_print_uint64
    call io_print_newline

    mov  rdi, lbl_cmp
    call io_print_string
    ASSERT_EQ64 r12, 3000

; =============================================================================
; TEST 6 — entropy_calculate: H = 8 (256 símbolos con freq=1, máximo)
; =============================================================================
    SECTION_HDR hdr_h8

    ; cargar frequency_table[i] = 1 ∀ i ∈ [0,255] directamente (sin frequency_count)
    ; simula un archivo con exactamente un byte de cada valor posible
    lea  rbx, [rel frequency_table]
    mov  rcx, 256
.fill_uniform:
    mov  qword [rbx], 1
    add  rbx, 8
    dec  rcx
    jnz  .fill_uniform

    mov  rdi, 256
    call entropy_calculate       ; ST0 = H = 8.0
                                 ; (log₂(1/256)=−8 exacto → 256×(1/256×8)=8)

    ST0_TO_MILLI r12             ; r12 = 8000

    mov  rdi, lbl_milli
    call io_print_string
    mov  rdi, r12
    call io_print_uint64
    call io_print_newline

    mov  rdi, lbl_exp
    call io_print_string
    mov  rdi, 8000
    call io_print_uint64
    call io_print_newline

    mov  rdi, lbl_cmp
    call io_print_string
    ASSERT_EQ64 r12, 8000

; =============================================================================
; FIN
; =============================================================================
    call io_print_newline
    SECTION_HDR hdr_done

    pop  r13
    pop  r12
    pop  rbx
    mov  rdi, 0
    call sys_exit
