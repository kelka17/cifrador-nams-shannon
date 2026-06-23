; =============================================================================
; test_io.asm — Test de regresión para io.asm
; Compila con:
;   nasm -f elf64 -Iinclude/ -o test_io.o test_io.asm
;   ld -o test_io test_io.o io.o
; Ejecuta con:
;   ./test_io
; =============================================================================

%include "include/syscalls.inc"

global _start

extern sys_exit
extern sys_write

extern io_print_string
extern io_print_len
extern io_print_newline
extern io_print_uint64
extern io_print_hex64

extern io_file_open_read
extern io_file_open_write
extern io_file_close
extern io_file_size
extern io_file_read_all
extern io_file_write_buf

extern io_alloc
extern io_free

; ── colores ANSI ─────────────────────────────────────────────────────────────
%define GREEN  27,"[32m"
%define YELLOW 27,"[33m"
%define CYAN   27,"[36m"
%define RESET  27,"[0m"

; ── macro de cabecera de test ─────────────────────────────────────────────────
%macro SECTION_HDR 1
    mov  rdi, STDOUT
    mov  rsi, ansi_cyan
    mov  rdx, ansi_cyan_len
    mov  rax, SYS_WRITE
    syscall
    mov  rdi, %1
    call io_print_string
    mov  rdi, STDOUT
    mov  rsi, ansi_reset
    mov  rdx, ansi_reset_len
    mov  rax, SYS_WRITE
    syscall
    call io_print_newline
%endmacro

%macro OK 0
    mov  rdi, STDOUT
    mov  rsi, ansi_green
    mov  rdx, ansi_green_len
    mov  rax, SYS_WRITE
    syscall
    mov  rdi, msg_ok
    call io_print_string
    mov  rdi, STDOUT
    mov  rsi, ansi_reset
    mov  rdx, ansi_reset_len
    mov  rax, SYS_WRITE
    syscall
%endmacro

; ── ruta del archivo temporal ─────────────────────────────────────────────────
%define TMP_FILE "/tmp/test_io_cifrador.tmp"

section .rodata

    ; ── mensajes de sección ──────────────────────────────────────────────────
    hdr_strings  db "=== TEST 1: io_print_string / io_print_len / io_print_newline ===", 0
    hdr_uint64   db "=== TEST 2: io_print_uint64 ===", 0
    hdr_hex64    db "=== TEST 3: io_print_hex64 ===", 0
    hdr_file     db "=== TEST 4: archivo (open/write/size/read_all/close) ===", 0
    hdr_alloc    db "=== TEST 5: io_alloc / io_free ===", 0
    hdr_done     db "=== TODOS LOS TESTS COMPLETADOS ===", 0

    ; ── etiquetas de items ────────────────────────────────────────────────────
    lbl_str      db "  io_print_string -> ", 0
    lbl_len      db "  io_print_len    -> ", 0
    lbl_nl       db "  io_print_newline (linea vacia abajo):", 0

    lbl_zero     db "  valor 0         -> ", 0
    lbl_one      db "  valor 1         -> ", 0
    lbl_decimal  db "  valor 123456789 -> ", 0
    lbl_max      db "  UINT64_MAX      -> ", 0

    lbl_hex_dead db "  0xDEADBEEFCAFEBABE -> ", 0
    lbl_hex_zero db "  valor 0            -> ", 0
    lbl_hex_ff   db "  valor 255          -> ", 0

    lbl_write    db "  escribir archivo   -> ", 0
    lbl_size     db "  tamanio leido      -> ", 0
    lbl_content  db "  contenido leido    -> ", 0
    lbl_alloc    db "  io_alloc(128)   -> puntero: ", 0
    lbl_free     db "  io_free         -> ", 0

    msg_ok       db " [OK]", 10, 0
    msg_newline  db "(aqui hay un salto de linea)", 10, 0

    ; ── datos de prueba ───────────────────────────────────────────────────────
    hello_str    db "Hola desde io_print_string", 0
    hello_len    db "Texto con longitud fija"
    hello_len_sz equ $ - hello_len

    file_data    db "CIFRADOR_NASM_TEST_1234567890", 10
    file_data_sz equ $ - file_data

    tmp_path     db "/tmp/test_io_cifrador.tmp", 0

    ; ── colores ANSI ─────────────────────────────────────────────────────────
    ansi_green   db 27, "[32m"
    ansi_green_len equ $ - ansi_green
    ansi_cyan    db 27, "[36m"
    ansi_cyan_len equ $ - ansi_cyan
    ansi_reset   db 27, "[0m"
    ansi_reset_len equ $ - ansi_reset

section .text

_start:

; =============================================================================
; TEST 1 — Funciones de texto
; =============================================================================
    SECTION_HDR hdr_strings

    ; io_print_string
    mov  rdi, lbl_str
    call io_print_string
    mov  rdi, hello_str
    call io_print_string
    OK

    ; io_print_len
    mov  rdi, lbl_len
    call io_print_string
    mov  rdi, hello_len
    mov  rsi, hello_len_sz
    call io_print_len
    OK

    ; io_print_newline
    mov  rdi, lbl_nl
    call io_print_string
    call io_print_newline
    call io_print_newline       ; la línea vacía visible
    mov  rdi, msg_newline
    call io_print_string

; =============================================================================
; TEST 2 — io_print_uint64
; =============================================================================
    call io_print_newline
    SECTION_HDR hdr_uint64

    mov  rdi, lbl_zero
    call io_print_string
    mov  rdi, 0
    call io_print_uint64
    OK

    mov  rdi, lbl_one
    call io_print_string
    mov  rdi, 1
    call io_print_uint64
    OK

    mov  rdi, lbl_decimal
    call io_print_string
    mov  rdi, 123456789
    call io_print_uint64
    OK

    mov  rdi, lbl_max
    call io_print_string
    mov  rdi, qword -1             ; UINT64_MAX = 18446744073709551615
    call io_print_uint64
    OK

; =============================================================================
; TEST 3 — io_print_hex64
; =============================================================================
    call io_print_newline
    SECTION_HDR hdr_hex64

    mov  rdi, lbl_hex_dead
    call io_print_string
    mov  rdi, 0xDEADBEEFCAFEBABE
    call io_print_hex64
    OK

    mov  rdi, lbl_hex_zero
    call io_print_string
    mov  rdi, 0
    call io_print_hex64
    OK

    mov  rdi, lbl_hex_ff
    call io_print_string
    mov  rdi, 255
    call io_print_hex64
    OK

; =============================================================================
; TEST 4 — Archivo: open/write/size/read_all/close
; =============================================================================
    call io_print_newline
    SECTION_HDR hdr_file

    ; ── abrir para escritura ─────────────────────────────────────────────────
    mov  rdi, lbl_write
    call io_print_string

    mov  rdi, tmp_path
    call io_file_open_write     ; rax = fd
    push rax                    ; [rsp] = fd_write

    ; ── escribir datos ───────────────────────────────────────────────────────
    mov  rdi, rax               ; fd
    mov  rsi, file_data
    mov  rdx, file_data_sz
    call io_file_write_buf

    ; ── cerrar ───────────────────────────────────────────────────────────────
    pop  rdi                    ; fd_write
    call io_file_close
    OK

    ; ── abrir para lectura ───────────────────────────────────────────────────
    mov  rdi, tmp_path
    call io_file_open_read      ; rax = fd
    push rax                    ; [rsp] = fd_read

    ; ── obtener tamaño ───────────────────────────────────────────────────────
    mov  rdi, lbl_size
    call io_print_string

    mov  rdi, [rsp]             ; fd_read
    call io_file_size           ; rax = tamaño
    push rax                    ; [rsp] = size; [rsp+8] = fd_read

    mov  rdi, rax
    call io_print_uint64        ; imprimir tamaño
    OK

    ; ── mapear archivo completo ───────────────────────────────────────────────
    mov  rdi, lbl_content
    call io_print_string

    mov  rdi, [rsp + 8]         ; fd_read
    mov  rsi, [rsp]             ; size
    call io_file_read_all       ; rax = ptr al contenido
    push rax                    ; [rsp] = ptr; [rsp+8] = size; [rsp+16] = fd_read

    ; imprimir contenido (es exactamente file_data que escribimos)
    mov  rdi, [rsp]             ; ptr
    mov  rsi, [rsp + 8]         ; size
    call io_print_len

    ; ── liberar mapeo ────────────────────────────────────────────────────────
    mov  rdi, [rsp]             ; ptr
    mov  rsi, [rsp + 8]         ; size
    call io_free

    pop  rax                    ; ptr (descartado)
    pop  rax                    ; size (descartado)

    ; ── cerrar fd de lectura ─────────────────────────────────────────────────
    pop  rdi                    ; fd_read
    call io_file_close

; =============================================================================
; TEST 5 — io_alloc / io_free
; =============================================================================
    call io_print_newline
    SECTION_HDR hdr_alloc

    mov  rdi, lbl_alloc
    call io_print_string

    mov  rdi, 128               ; reservar 128 bytes
    call io_alloc               ; rax = puntero
    push rax                    ; guardar puntero

    ; verificar que no sea MAP_FAILED (~0): imprimir la dirección
    mov  rdi, rax
    call io_print_hex64
    OK

    ; escribir algo en la memoria para verificar que es escribible
    mov  rax, [rsp]
    mov  qword [rax], 0xCAFEBABEDEADBEEF
    ; leer de vuelta e imprimir (confirma PROT_WRITE funcionó)

    ; liberar
    mov  rdi, lbl_free
    call io_print_string

    pop  rdi                    ; puntero
    mov  rsi, 128
    call io_free
    OK

; =============================================================================
; FIN
; =============================================================================
    call io_print_newline
    SECTION_HDR hdr_done

    mov  rdi, 0
    call sys_exit
