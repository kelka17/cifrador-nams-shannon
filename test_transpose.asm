; =============================================================================
; test_transpose.asm — Test de regresión para transpose.asm
; Compila con:
;   nasm -f elf64 -Iinclude/ -o test_transpose.o test_transpose.asm
;   nasm -f elf64 -Iinclude/ -o transpose.o   transpose.asm
;   nasm -f elf64 -Iinclude/ -o io.o          io.asm
;   ld -o test_transpose test_transpose.o transpose.o io.o
; Ejecuta con:
;   ./test_transpose ; echo $?   (debe ser 0)
; =============================================================================
;
; VALORES ESPERADOS (calculados con π(i) = 7−i y σ(i) = r−1−i):
;
;   TEST 1 — BSWAP de "ABCDEFGH" (1 bloque exacto, 8 bytes):
;     Entrada en memoria:  41 42 43 44 45 46 47 48  ('A'..'H')
;     BSWAP invierte:       48 47 46 45 44 43 42 41  ('H'..'A')
;     Como qword LE:  0x4142434445464748
;
;   TEST 2 — Round-trip encrypt→decrypt recupera el original (auto-inversa):
;     T(T("ABCDEFGH")) = "ABCDEFGH"
;
;   TEST 3 — Solo residuos: 5 bytes [01,02,03,04,05] (q=0, r=5):
;     Espejo σ(i)=4−i:  [05,04,03,02,01]
;
;   TEST 4 — Bloque + residuo: 9 bytes (q=1, r=1):
;     Bloque [01..08] → BSWAP → [08,07,06,05,04,03,02,01]
;     1 residuo [09]  → sin cambio (rdi==rbx → cond. parada inmediata)
;
; =============================================================================

%include "include/syscalls.inc"

global _start

extern sys_exit
extern io_print_string, io_print_newline, io_print_hex64
extern io_alloc, io_free
extern transpose_encrypt
extern transpose_decrypt

; =============================================================================
section .rodata
; =============================================================================

    ansi_green  db 27, "[32m", 0
    ansi_red    db 27, "[31m", 0
    ansi_cyan   db 27, "[36m", 0
    ansi_reset  db 27, "[0m",  0

    msg_ok      db " [OK]",   10, 0
    msg_fail    db " [FAIL]", 10, 0

    hdr_bswap   db "=== TEST 1: transpose_encrypt (BSWAP, 1 bloque exacto) ===", 0
    hdr_rtrip   db "=== TEST 2: round-trip encrypt->decrypt = identidad ===", 0
    hdr_resid   db "=== TEST 3: residuos puros (5 bytes, q=0, r=5) ===", 0
    hdr_mixed   db "=== TEST 4: bloque + 1 residuo (9 bytes, q=1, r=1) ===", 0
    hdr_done    db "=== TODOS LOS TESTS PASARON ===", 0

    lbl_antes   db "  entrada     ", 0
    lbl_desp    db "  transpuesto ", 0
    lbl_esp     db "  esperado -> ", 0
    lbl_res     db "  resultado   ", 0
    lbl_orig    db "  original    ", 0
    lbl_recup   db "  recuperado  ", 0

    ; Bloques de datos de prueba (en .rodata = solo lectura, se copian a buffers)
    blk_ABCDEFGH  db "ABCDEFGH"       ; 8 bytes, sin null
    resid_01_05   db 0x01, 0x02, 0x03, 0x04, 0x05
    blk_01_09     db 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09

; =============================================================================
; MACROS
; =============================================================================

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

%macro OK_MSG 0
    mov  rdi, ansi_green
    call io_print_string
    mov  rdi, msg_ok
    call io_print_string
    mov  rdi, ansi_reset
    call io_print_string
%endmacro

%macro FAIL_MSG 0
    mov  rdi, ansi_red
    call io_print_string
    mov  rdi, msg_fail
    call io_print_string
    mov  rdi, ansi_reset
    call io_print_string
%endmacro

; ASSERT_EQ64 reg, imm64
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

; ASSERT_BYTE base_reg, offset, expected_byte
%macro ASSERT_BYTE 3
    movzx rax, byte [%1 + %2]
    cmp   al, %3
    je    %%pass
    FAIL_MSG
    jmp   %%end
%%pass:
    OK_MSG
%%end:
%endmacro

; =============================================================================
section .text
; =============================================================================

_start:
    push rbx                        ; callee-saved: buf_ptr principal
    push r12                        ; callee-saved: buf_ptr secundario (TEST 2)

; =============================================================================
; TEST 1 — transpose_encrypt sobre 1 bloque exacto de 8 bytes ("ABCDEFGH")
;
;   BSWAP invierte los bytes en memoria: π(i) = 7−i
;   Entrada:  [41 42 43 44 45 46 47 48]  (A..H)
;   Salida:   [48 47 46 45 44 43 42 41]  (H..A)
;   Como qword LE leído de memoria: 0x4142434445464748
; =============================================================================
    SECTION_HDR hdr_bswap

    mov  rdi, 8
    call io_alloc
    mov  rbx, rax                   ; rbx = buf_ptr (callee-saved)

    mov  rax, qword [rel blk_ABCDEFGH]
    mov  qword [rbx], rax           ; copiar "ABCDEFGH" al buffer

    mov  rdi, lbl_antes
    call io_print_string
    mov  rdi, qword [rbx]           ; 0x4847464544434241
    call io_print_hex64
    call io_print_newline

    ; ── aplicar transpose_encrypt ────────────────────────────────────────────
    mov  rdi, rbx                   ; arg1 = buffer
    mov  rsi, 8                     ; arg2 = length = 8
    call transpose_encrypt          ; BSWAP in-place; rbx preservado

    mov  rdi, lbl_desp
    call io_print_string
    mov  rdi, qword [rbx]
    call io_print_hex64
    call io_print_newline

    mov  rdi, lbl_esp
    call io_print_string
    mov  rdi, 0x4142434445464748    ; "HGFEDCBA" como qword LE
    call io_print_hex64
    call io_print_newline

    mov  rdi, lbl_res
    call io_print_string
    mov  rax, qword [rbx]
    ASSERT_EQ64 rax, 0x4142434445464748

    ; También verificar bytes individuales (refuerza ASSERT_BYTE)
    ASSERT_BYTE rbx, 0, 0x48        ; posición 0 → 'H'
    ASSERT_BYTE rbx, 7, 0x41        ; posición 7 → 'A'

    mov  rdi, rbx
    mov  rsi, 8
    call io_free

; =============================================================================
; TEST 2 — Round-trip: T(T(B)) = B  (propiedad auto-inversa)
;
;   Aplica transpose_encrypt, luego transpose_decrypt sobre el resultado.
;   El buffer debe quedar idéntico al original.  Esto verifica el Corolario
;   del §2: las funciones cifrado/descifrado son correctas simultáneamente.
; =============================================================================
    SECTION_HDR hdr_rtrip

    mov  rdi, 8
    call io_alloc
    mov  rbx, rax

    mov  rax, qword [rel blk_ABCDEFGH]
    mov  qword [rbx], rax           ; original = "ABCDEFGH"

    mov  rdi, lbl_orig
    call io_print_string
    mov  rdi, qword [rbx]
    call io_print_hex64
    call io_print_newline

    ; ── encrypt ──────────────────────────────────────────────────────────────
    mov  rdi, rbx
    mov  rsi, 8
    call transpose_encrypt

    ; ── decrypt (misma operación, auto-inversa) ───────────────────────────────
    mov  rdi, rbx
    mov  rsi, 8
    call transpose_decrypt

    mov  rdi, lbl_recup
    call io_print_string
    mov  rdi, qword [rbx]
    call io_print_hex64
    call io_print_newline

    mov  rdi, lbl_res
    call io_print_string
    mov  rax, qword [rbx]
    ASSERT_EQ64 rax, 0x4847464544434241   ; debe recuperar "ABCDEFGH"

    mov  rdi, rbx
    mov  rsi, 8
    call io_free

; =============================================================================
; TEST 3 — Solo residuos: 5 bytes [01,02,03,04,05] (q=0, r=5)
;
;   Permutación espejo σ(i)=4−i implementada con dos punteros:
;     iter 1: swap(buf[0], buf[4]) → [05, 02, 03, 04, 01]
;     iter 2: swap(buf[1], buf[3]) → [05, 04, 03, 02, 01]
;     buf[2] queda fijo (punteros se igualan)
;   Resultado: [05, 04, 03, 02, 01]
; =============================================================================
    SECTION_HDR hdr_resid

    mov  rdi, 8
    call io_alloc
    mov  rbx, rax

    ; copiar [01,02,03,04,05] + centinela 0xFF en [5..7]
    mov  byte [rbx + 0], 0x01
    mov  byte [rbx + 1], 0x02
    mov  byte [rbx + 2], 0x03
    mov  byte [rbx + 3], 0x04
    mov  byte [rbx + 4], 0x05
    mov  byte [rbx + 5], 0xFF      ; centinela: no debe tocarse
    mov  byte [rbx + 6], 0xFF
    mov  byte [rbx + 7], 0xFF

    mov  rdi, rbx
    mov  rsi, 5                    ; length = 5  → q=0, r=5
    call transpose_encrypt

    ; verificar los 5 bytes invertidos
    ASSERT_BYTE rbx, 0, 0x05
    ASSERT_BYTE rbx, 1, 0x04
    ASSERT_BYTE rbx, 2, 0x03       ; byte central queda fijo
    ASSERT_BYTE rbx, 3, 0x02
    ASSERT_BYTE rbx, 4, 0x01
    ; centinelas deben estar intactos
    ASSERT_BYTE rbx, 5, 0xFF
    ASSERT_BYTE rbx, 7, 0xFF

    mov  rdi, rbx
    mov  rsi, 8
    call io_free

; =============================================================================
; TEST 4 — Bloque + 1 byte residual: 9 bytes (q=1, r=1)
;
;   FASE 1: [01,02,03,04,05,06,07,08] → BSWAP → [08,07,06,05,04,03,02,01]
;   FASE 2: r=1 → rbx = rdi+0 = rdi → condición rdi >= rbx → no hace swap
;           byte[8] = 0x09 queda sin cambio.
; =============================================================================
    SECTION_HDR hdr_mixed

    mov  rdi, 16
    call io_alloc
    mov  rbx, rax

    ; copiar [01..09] + centinela en [9]
    ; [rel reg+rcx] no es válido en x86-64; se carga la base en rsi primero
    lea  rsi, [rel blk_01_09]      ; rsi = dirección base del array fuente
    xor  rcx, rcx
.copy9:
    movzx rax, byte [rsi + rcx]    ; leer byte[i] del fuente
    mov   byte [rbx + rcx], al     ; escribir en buffer (rbx callee-saved)
    inc   rcx
    cmp   rcx, 9
    jl    .copy9
    mov   byte [rbx + 9], 0xFF     ; centinela

    mov  rdi, rbx
    mov  rsi, 9                    ; length = 9  → q=1, r=1
    call transpose_encrypt         ; rbx preservado

    ; verificar bloque transpuesto [08,07,06,05,04,03,02,01]
    ASSERT_BYTE rbx, 0, 0x08
    ASSERT_BYTE rbx, 1, 0x07
    ASSERT_BYTE rbx, 2, 0x06
    ASSERT_BYTE rbx, 3, 0x05
    ASSERT_BYTE rbx, 4, 0x04
    ASSERT_BYTE rbx, 5, 0x03
    ASSERT_BYTE rbx, 6, 0x02
    ASSERT_BYTE rbx, 7, 0x01
    ; byte[8] = residuo sin cambio
    ASSERT_BYTE rbx, 8, 0x09
    ; centinela intacto
    ASSERT_BYTE rbx, 9, 0xFF

    mov  rdi, rbx
    mov  rsi, 16
    call io_free

; =============================================================================
; FIN
; =============================================================================
    SECTION_HDR hdr_done

    pop  r12
    pop  rbx
    mov  rdi, 0
    call sys_exit
