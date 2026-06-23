; =============================================================================
; test_cipher.asm — Test de regresión para cipher.asm
; Compila con:
;   nasm -f elf64 -Iinclude/ -o test_cipher.o test_cipher.asm
;   nasm -f elf64 -Iinclude/ -o cipher.o   cipher.asm
;   nasm -f elf64 -Iinclude/ -o io.o       io.asm
;   ld -o test_cipher test_cipher.o cipher.o io.o
; Ejecuta con:
;   ./test_cipher ; echo $?   (debe ser 0)
; =============================================================================
;
; VALORES ESPERADOS (calculados a mano, verificados byte a byte):
;
;   Clave ASCII "KEY12345" → key64 little-endian:
;     byte[0]='K'=0x4B  byte[1]='E'=0x45  byte[2]='Y'=0x59  byte[3]='1'=0x31
;     byte[4]='2'=0x32  byte[5]='3'=0x33  byte[6]='4'=0x34  byte[7]='5'=0x35
;     qword (MSB→LSB) = 0x353433323159454B
;
;   Plaintext "ABCDEFGH" (1 bloque exacto, 8 bytes):
;     qword LE = 0x4847464544434241
;
;   Ciphertext = plaintext XOR key64, byte a byte:
;     A^K=0x41^0x4B=0x0A  B^E=0x42^0x45=0x07  C^Y=0x43^0x59=0x1A  D^1=0x44^0x31=0x75
;     E^2=0x45^0x32=0x77  F^3=0x46^0x33=0x75  G^4=0x47^0x34=0x73  H^5=0x48^0x35=0x7D
;     qword LE = 0x7D737577751A070A
;
;   Descifrado = ciphertext XOR key64 (misma operacion XOR):
;     0x0A^0x4B=0x41='A'  0x07^0x45=0x42='B'  0x1A^0x59=0x43='C'  0x75^0x31=0x44='D'
;     0x77^0x32=0x45='E'  0x75^0x33=0x46='F'  0x73^0x34=0x47='G'  0x7D^0x35=0x48='H'
;     qword LE = 0x4847464544434241  (identico al plaintext original)
;
; =============================================================================

%include "include/syscalls.inc"

global _start

extern sys_exit
extern io_print_string, io_print_newline, io_print_hex64
extern io_alloc, io_free
extern cipher_build_key64
extern cipher_xor

; =============================================================================
section .rodata
; =============================================================================

    ansi_green   db 27, "[32m", 0
    ansi_red     db 27, "[31m", 0
    ansi_cyan    db 27, "[36m", 0
    ansi_reset   db 27, "[0m",  0

    msg_ok       db " [OK]",   10, 0
    msg_fail     db " [FAIL]", 10, 0

    hdr_build    db "=== TEST 1: cipher_build_key64 ===", 0
    hdr_xor      db "=== TEST 2: cipher_xor (cifrado, 1 bloque) ===", 0
    hdr_decrypt  db "=== TEST 3: cipher_xor (descifrado = misma operacion XOR) ===", 0
    hdr_done     db "=== TODOS LOS TESTS PASARON ===", 0

    lbl_key_exp  db "  esperada -> ", 0
    lbl_key_got  db "  obtenida -> ", 0
    lbl_key_cmp  db "  resultado   ", 0
    lbl_pt       db "  plaintext   ", 0
    lbl_ct_got   db "  cifrado  -> ", 0
    lbl_ct_exp   db "  esperado -> ", 0
    lbl_ct_cmp   db "  resultado   ", 0
    lbl_dc_in    db "  ciphertext  ", 0
    lbl_dc_got   db "  descifrado  ", 0
    lbl_dc_exp   db "  esperado -> ", 0
    lbl_dc_cmp   db "  resultado   ", 0

    key_str      db "KEY12345", 0   ; null-terminated
    plaintext    db "ABCDEFGH"      ; 8 bytes exactos, SIN null

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

; ASSERT_EQ64 got_reg, expected_imm64
;   Compara got_reg con un valor de 64 bits cargado en r11 (caller-saved).
;   Imprime OK o FAIL. Destruye rdi (para los print).
;   No destruye got_reg si es callee-saved (r12..r15, rbx).
%macro ASSERT_EQ64 2
    mov  r11, %2               ; r11 = valor esperado (evita CMP imm64 inválido)
    cmp  %1, r11
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
    push rbx                        ; callee-saved: usado para buf_ptr en TEST 2
    push r12                        ; callee-saved: usado para guardar key64 en TEST 1

; =============================================================================
; TEST 1 — cipher_build_key64("KEY12345")
;   System V AMD64: rdi = puntero a cadena → rax = key64
; =============================================================================
    SECTION_HDR hdr_build

    mov  rdi, lbl_key_exp
    call io_print_string
    mov  rdi, 0x353433323159454B    ; valor esperado
    call io_print_hex64
    call io_print_newline

    ; ── construir clave ──────────────────────────────────────────────────────
    mov  rdi, key_str               ; arg1 = "KEY12345"
    call cipher_build_key64         ; rax = key64
    mov  r12, rax                   ; preservar en callee-saved (calls destruyen rax)

    mov  rdi, lbl_key_got
    call io_print_string
    mov  rdi, r12
    call io_print_hex64
    call io_print_newline

    mov  rdi, lbl_key_cmp
    call io_print_string
    ASSERT_EQ64 r12, 0x353433323159454B

; =============================================================================
; TEST 2 — cipher_xor("ABCDEFGH", 8, key64)
;   Verifica que el ciphertext resultante es 0x7D737577751A070A
; =============================================================================
    SECTION_HDR hdr_xor

    ; ── asignar buffer de 8 bytes ────────────────────────────────────────────
    mov  rdi, 8
    call io_alloc                   ; rax = buf_ptr
    mov  rbx, rax                   ; rbx = buf_ptr (callee-saved)

    ; ── copiar "ABCDEFGH" al buffer ──────────────────────────────────────────
    mov  rax, qword [rel plaintext] ; carga los 8 bytes como un qword LE
    mov  qword [rbx], rax           ; buffer[0..7] = "ABCDEFGH"

    ; ── mostrar plaintext ────────────────────────────────────────────────────
    mov  rdi, lbl_pt
    call io_print_string
    mov  rdi, qword [rbx]           ; 0x4847464544434241
    call io_print_hex64
    call io_print_newline

    ; ── cifrar: cipher_xor(buf, 8, key64)  [System V AMD64] ──────────────────
    mov  rdi, rbx                   ; arg1 = puntero al buffer
    mov  rsi, 8                     ; arg2 = longitud (1 bloque exacto)
    mov  rdx, r12                   ; arg3 = key64 (r12 callee-saved = aún válido)
    call cipher_xor                 ; cifra in-place; rbx preservado

    ; ── mostrar ciphertext obtenido y esperado ───────────────────────────────
    mov  rdi, lbl_ct_got
    call io_print_string
    mov  rdi, qword [rbx]           ; leer resultado cifrado
    call io_print_hex64
    call io_print_newline

    mov  rdi, lbl_ct_exp
    call io_print_string
    mov  rdi, 0x7D737577751A070A    ; valor esperado
    call io_print_hex64
    call io_print_newline

    ; ── comparar resultado ───────────────────────────────────────────────────
    mov  rdi, lbl_ct_cmp
    call io_print_string
    mov  rax, qword [rbx]           ; ciphertext obtenido en rax
    ASSERT_EQ64 rax, 0x7D737577751A070A

    ; ── liberar buffer ────────────────────────────────────────────────────────
    mov  rdi, rbx
    mov  rsi, 8
    call io_free

; =============================================================================
; TEST 3 — cipher_xor aplicado al ciphertext → recupera el plaintext original
;
;   PRINCIPIO: XOR es auto-inverso. Si C = P XOR K, entonces C XOR K = P.
;   La MISMA función cipher_xor sirve tanto para cifrar como para descifrar.
;   Solo cambia el contenido del buffer de entrada (plaintext vs ciphertext).
; =============================================================================
    SECTION_HDR hdr_decrypt

    ; ── asignar buffer y cargar el ciphertext conocido (TEST 2) ─────────────
    mov  rdi, 8
    call io_alloc                   ; rax = buf_ptr
    mov  rbx, rax                   ; rbx = buf_ptr (callee-saved)

    mov  rax, 0x7D737577751A070A    ; ciphertext del TEST 2
    mov  qword [rbx], rax

    ; ── mostrar ciphertext de entrada ────────────────────────────────────────
    mov  rdi, lbl_dc_in
    call io_print_string
    mov  rdi, qword [rbx]
    call io_print_hex64
    call io_print_newline

    ; ── descifrar: cipher_xor(buf, 8, key64)  [misma llamada que al cifrar] ──
    mov  rdi, rbx                   ; arg1 = buffer con ciphertext
    mov  rsi, 8                     ; arg2 = longitud
    mov  rdx, r12                   ; arg3 = misma key64 (r12 aún válido)
    call cipher_xor                 ; descifra in-place

    ; ── mostrar resultado obtenido vs plaintext esperado ─────────────────────
    mov  rdi, lbl_dc_got
    call io_print_string
    mov  rdi, qword [rbx]
    call io_print_hex64
    call io_print_newline

    mov  rdi, lbl_dc_exp
    call io_print_string
    mov  rdi, 0x4847464544434241    ; "ABCDEFGH" como qword LE
    call io_print_hex64
    call io_print_newline

    ; ── verificar que se recuperó el plaintext exacto ────────────────────────
    mov  rdi, lbl_dc_cmp
    call io_print_string
    mov  rax, qword [rbx]
    ASSERT_EQ64 rax, 0x4847464544434241

    ; ── liberar buffer ────────────────────────────────────────────────────────
    mov  rdi, rbx
    mov  rsi, 8
    call io_free

; =============================================================================
; FIN
; =============================================================================
    SECTION_HDR hdr_done

    pop  r12
    pop  rbx
    mov  rdi, 0
    call sys_exit
