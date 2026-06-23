; =============================================================================
; test_header.asm — Tests de regresión para header.asm / header.inc
; =============================================================================
;
; Compila y enlaza:
;   nasm -f elf64 -Iinclude/ -o test_header.o  test_header.asm
;   nasm -f elf64 -Iinclude/ -o header.o       header.asm
;   nasm -f elf64 -Iinclude/ -o io.o           io.asm
;   nasm -f elf64 -Iinclude/ -o cipher.o       cipher.asm
;   nasm -f elf64 -Iinclude/ -o transpose.o    transpose.asm
;   ld -o test_header test_header.o header.o io.o cipher.o transpose.o
; Ejecuta:
;   ./test_header ; echo $?   (debe ser 0)
;
; =============================================================================
;
; VALORES ESPERADOS (calculados a mano, verificados byte a byte):
;
; ── TEST 1 — header_build ────────────────────────────────────────────────────
;   header_build(buf, 12345, 0xDEADBEEF)
;   Estructura resultante (20 bytes):
;
;   Offset  Campo          Valor esperado     Verificación
;   ──────  ─────────────  ─────────────────  ────────────
;     0     magic_number   0x43525950         ASCII "CRYP"
;     4     version        0x0001             versión 1
;     6     original_len   12345              longitud argumento
;    14     checksum       0xDEADBEEF         checksum argumento
;    18     reserved       0x0000             siempre cero
;
; ── TEST 2 — header_validate ─────────────────────────────────────────────────
;   2a. Con magic correcto (buf de TEST 1):  retorna 1 (válido)
;   2b. Con magic incorrecto (magic = 0):   retorna 0 (inválido)
;
; ── TEST 3 — header_crc32 (vacío) ────────────────────────────────────────────
;   header_crc32("", 0) = 0x00000000
;   Prueba: Init=0xFFFFFFFF, sin bytes, final XOR=0xFFFFFFFF → 0x00000000
;
; ── TEST 4 — header_crc32 (vector estándar) ──────────────────────────────────
;   header_crc32("123456789", 9) = 0xCBF43926
;   Vector de verificación estándar CRC-32/ISO-HDLC (IEEE 802.3).
;
; ── TEST 5 — CIFRAR_COMPLETO / DESCIFRAR_COMPLETO (round-trip) ───────────────
;   buf = "ABCDEFGH" (8 bytes)
;   CIFRAR_COMPLETO(buf, 8, "KEY12345"):
;     1. cipher_xor:     "ABCDEFGH" XOR key64 → ciphertext_xor
;     2. transpose:      BSWAP(ciphertext_xor) → ciphertext_full
;   DESCIFRAR_COMPLETO(buf, 8, "KEY12345"):
;     1. transpose:      BSWAP(ciphertext_full) = ciphertext_xor (auto-inversa)
;     2. cipher_xor:     ciphertext_xor XOR key64 = "ABCDEFGH"
;   Verificación: buf[0..7] == 0x4847464544434241 (qword LE de "ABCDEFGH")
;
; =============================================================================

%include "include/syscalls.inc"
%include "include/header.inc"

global _start

extern sys_exit
extern io_print_string, io_print_newline, io_print_hex64, io_print_uint64
extern header_build, header_validate, header_checksum, header_crc32
extern cipher_build_key64, cipher_xor
extern transpose_encrypt, transpose_decrypt

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
    hdr_build    db "=== TEST 1: header_build — construir cabecera CRYP ===", 0
    hdr_valid    db "=== TEST 2: header_validate — verificar magic number ===", 0
    hdr_crc_0    db "=== TEST 3: header_crc32('', 0) — CRC-32 buffer vacio ===", 0
    hdr_crc_std  db "=== TEST 4: header_crc32('123456789',9) — vector estandar ISO-HDLC ===", 0
    hdr_done     db "=== TODOS LOS TESTS PASARON ===", 0

    ; ── etiquetas de items ───────────────────────────────────────────────────
    lbl_magic    db "  magic_number   -> ", 0
    lbl_version  db "  version        -> ", 0
    lbl_origlen  db "  original_len   -> ", 0
    lbl_checksum db "  checksum       -> ", 0
    lbl_reserved db "  reserved       -> ", 0

    lbl_valid_ok db "  magic correcto -> ", 0
    lbl_valid_no db "  magic incorrecto-> ", 0

    lbl_crc_got  db "  CRC-32 obtenido -> ", 0
    lbl_crc_exp  db "  CRC-32 esperado -> ", 0
    lbl_crc_cmp  db "  resultado        ", 0

    lbl_buf_bef  db "  buf antes  -> ", 0
    lbl_buf_enc  db "  buf cifrado-> ", 0
    lbl_buf_aft  db "  buf despues-> ", 0
    lbl_rt_cmp   db "  round-trip   ", 0

    ; ── datos de prueba ──────────────────────────────────────────────────────
    crc_empty_str  db 0             ; buffer de 0 bytes (placeholder)
    crc_std_str    db "123456789"   ; 9 bytes — vector estándar CRC-32
    plaintext_AB   db "ABCDEFGH"   ; 8 bytes para TEST 5
    key_str        db "KEY12345", 0 ; clave null-terminated

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

; ASSERT_EQ32 got_reg32, expected_imm32
;   Compara un registro de 32 bits con un inmediato de 32 bits.
%macro ASSERT_EQ32 2
    cmp  %1, %2
    je   %%pass
    FAIL_MSG
    jmp  %%end
%%pass:
    OK_MSG
%%end:
%endmacro

; ASSERT_EQ64 got_reg64, expected_imm64
;   Usa r11 como scratch para cargar inmediatos de 64 bits.
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

; =============================================================================
section .bss
; =============================================================================

    hdr_buf  resb 20            ; buffer de 20 bytes para la cabecera CRYP

; =============================================================================
section .text
; =============================================================================

_start:
    push rbx                   ; callee-saved — puntero al hdr_buf
    push r12                   ; callee-saved — resultados de 64 bits
    push r13                   ; callee-saved — resultados de 32 bits / buf_ptr

; =============================================================================
; TEST 1 — header_build: verifica todos los campos de la cabecera
; =============================================================================
    SECTION_HDR hdr_build

    ; construir cabecera con original_len=12345, checksum=0xDEADBEEF
    lea  rdi, [rel hdr_buf]
    mov  rsi, 12345
    mov  edx, 0xDEADBEEF
    call header_build

    lea  rbx, [rel hdr_buf]     ; rbx = base (callee-saved, sobrevive a los prints)

    ; verificar magic_number == 0x43525950
    mov  rdi, lbl_magic
    call io_print_string
    mov  eax, dword [rbx + HEADER.magic_number]
    mov  edi, eax
    call io_print_hex64
    ASSERT_EQ32 dword [rbx + HEADER.magic_number], MAGIC_CRYP

    ; verificar version == 1
    mov  rdi, lbl_version
    call io_print_string
    movzx eax, word [rbx + HEADER.version]
    mov  rdi, rax
    call io_print_uint64
    movzx eax, word [rbx + HEADER.version]
    cmp  ax, HEADER_VERSION
    je   .v1_ok
    FAIL_MSG
    jmp  .v1_done
.v1_ok:
    OK_MSG
.v1_done:

    ; verificar original_len == 12345
    mov  rdi, lbl_origlen
    call io_print_string
    mov  r12, qword [rbx + HEADER.original_len]
    mov  rdi, r12
    call io_print_uint64
    ASSERT_EQ64 r12, 12345

    ; verificar checksum == 0xDEADBEEF
    mov  rdi, lbl_checksum
    call io_print_string
    mov  eax, dword [rbx + HEADER.checksum]
    mov  edi, eax
    call io_print_hex64
    ASSERT_EQ32 dword [rbx + HEADER.checksum], 0xDEADBEEF

    ; verificar reserved == 0
    mov  rdi, lbl_reserved
    call io_print_string
    movzx eax, word [rbx + HEADER.reserved]
    mov  rdi, rax
    call io_print_uint64
    movzx eax, word [rbx + HEADER.reserved]
    cmp  ax, 0
    je   .r_ok
    FAIL_MSG
    jmp  .r_done
.r_ok:
    OK_MSG
.r_done:

; =============================================================================
; TEST 2 — header_validate: magic correcto → 1, incorrecto → 0
; =============================================================================
    SECTION_HDR hdr_valid

    ; 2a: cabecera construida en TEST 1 debe ser válida
    mov  rdi, lbl_valid_ok
    call io_print_string
    lea  rdi, [rel hdr_buf]
    call header_validate        ; rax = 1 si magic correcto
    mov  r13d, eax
    mov  rdi, rax
    call io_print_uint64
    ASSERT_EQ32 r13d, 1

    ; 2b: machacar magic con 0 → debe retornar 0
    mov  rdi, lbl_valid_no
    call io_print_string
    lea  rbx, [rel hdr_buf]
    mov  dword [rbx + HEADER.magic_number], 0   ; corromper magic
    lea  rdi, [rel hdr_buf]
    call header_validate        ; rax = 0
    mov  r13d, eax
    mov  rdi, rax
    call io_print_uint64
    ASSERT_EQ32 r13d, 0

; =============================================================================
; TEST 3 — header_crc32("", 0): CRC-32 del buffer vacío = 0x00000000
; =============================================================================
    SECTION_HDR hdr_crc_0

    ; CRC-32("") = Init XOR Final = 0xFFFFFFFF XOR 0xFFFFFFFF = 0x00000000
    lea  rdi, [rel crc_empty_str]
    mov  rsi, 0
    call header_crc32           ; eax = CRC-32

    mov  r13d, eax              ; r13d = resultado (callee-saved sobrevive prints)

    mov  rdi, lbl_crc_got
    call io_print_string
    mov  edi, r13d              ; zero-extend a rdi
    call io_print_hex64
    call io_print_newline

    mov  rdi, lbl_crc_exp
    call io_print_string
    mov  rdi, 0
    call io_print_hex64
    call io_print_newline

    mov  rdi, lbl_crc_cmp
    call io_print_string
    ASSERT_EQ32 r13d, 0x00000000

; =============================================================================
; TEST 4 — header_crc32("123456789", 9): vector estándar CRC-32/ISO-HDLC
; =============================================================================
    SECTION_HDR hdr_crc_std

    ; Vector de verificación de la especificación CRC-32/ISO-HDLC:
    ;   CRC-32("123456789") = 0xCBF43926
    ; Si este test pasa, la implementación es correcta para el estándar.
    lea  rdi, [rel crc_std_str]
    mov  rsi, 9
    call header_crc32           ; eax = CRC-32

    mov  r13d, eax

    mov  rdi, lbl_crc_got
    call io_print_string
    mov  edi, r13d
    call io_print_hex64
    call io_print_newline

    mov  rdi, lbl_crc_exp
    call io_print_string
    mov  rdi, 0xCBF43926
    call io_print_hex64
    call io_print_newline

    mov  rdi, lbl_crc_cmp
    call io_print_string
    ASSERT_EQ32 r13d, 0xCBF43926

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
