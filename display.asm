; =============================================================================
; Archivo:     display.asm
; Proyecto:    Cifrador/Descifrador con Análisis de Entropía de Shannon
; Asignatura:  Taller de Programación en Bajo Nivel
; Descripción: Histograma ASCII con colores ANSI y panel de entropía Shannon.
; =============================================================================

%include "include/syscalls.inc"
%include "include/macros.inc"

global display_histogram
global display_error
global display_entropy_panel

extern sys_write
extern io_print_string
extern io_print_len
extern io_print_uint64

%define BAR_MAX 40              ; ancho máximo de barra en columnas

; =============================================================================
section .rodata
; =============================================================================

    ; ── secuencias ANSI (null-terminated para io_print_string) ───────────────
    ansi_reset  db 0x1B, "[0m",  0   ; restaurar atributos
    ansi_bold   db 0x1B, "[1m",  0   ; negrita
    ansi_cyan   db 0x1B, "[36m", 0   ; color barra histograma
    ansi_yellow db 0x1B, "[33m", 0   ; color entropía

    ; ── histograma ────────────────────────────────────────────────────────────
    str_hist_title db 10, 0x1B, "[1m", "  HISTOGRAMA DE DISTRIBUCION DE BYTES"
                   db 0x1B, "[0m", 10, 0
    str_hist_hdr   db "  BYTE   DISTRIBUCION                           CONTEO", 10
                   db "  -----  ----------------------------------------  -------", 10, 0
    str_no_data    db "  (tabla de frecuencias vacia)", 10, 0
    str_0x         db "  0x", 0      ; prefijo de cada fila
    str_two_sp     db "  ", 0        ; separador byte → barra
    str_row_end    db "  ", 0        ; separador barra → conteo
    str_nl         db 10, 0          ; fin de fila

    ; ── panel de entropía ─────────────────────────────────────────────────────
    str_ent_title  db 10, 0x1B, "[1m", "  ENTROPIA DE SHANNON"
                   db 0x1B, "[0m", 10, 0
    str_ent_bef    db "  Antes del cifrado :   ", 0
    str_ent_aft    db "  Despues del cifrado:  ", 0
    str_bits       db " bits/byte", 10, 0
    str_dot        db ".", 0
    str_zero1      db "0", 0         ; un cero inicial para fracción 10..99
    str_zero2      db "00", 0        ; dos ceros para fracción 0..9

; =============================================================================
section .bss
; =============================================================================

    dh_hex2  resb 3             ; 2 nibbles ASCII para etiqueta de byte
    bar_buf  resb 44            ; buffer compartido: barras '#' y relleno ' '

; =============================================================================
section .text
; =============================================================================

; =============================================================================
; display_entropy_panel — Panel comparativo antes/después del cifrado
; =============================================================================
; void display_entropy_panel(uint64_t h_before_milli, uint64_t h_after_milli)
;   rdi = H_antes   × 1000  (p.ej. 7234 para 7.234 bits/byte)
;   rsi = H_después × 1000
;
; Convención de llamada: System V AMD64 ABI
;   Callee-saved empleados: rbx (h_before_milli), r12 (h_after_milli)
display_entropy_panel:
    push rbx                    ; preservar registro callee-saved (ABI)
    push r12                    ; preservar registro callee-saved (ABI)

    mov  rbx, rdi               ; rbx = h_before_milli (sobrevive llamadas)
    mov  r12, rsi               ; r12 = h_after_milli  (sobrevive llamadas)

    lea  rdi, [rel str_ent_title]
    call io_print_string        ; título en negrita

    lea  rdi, [rel ansi_yellow]
    call io_print_string        ; color amarillo para valores

    lea  rdi, [rel str_ent_bef]
    call io_print_string

    mov  rdi, rbx               ; pasar h_before_milli
    call dep_print_milli        ; imprime "X.YYY"

    lea  rdi, [rel ansi_reset]
    call io_print_string

    lea  rdi, [rel str_bits]
    call io_print_string        ; " bits/byte\n"

    lea  rdi, [rel ansi_yellow]
    call io_print_string

    lea  rdi, [rel str_ent_aft]
    call io_print_string

    mov  rdi, r12               ; pasar h_after_milli
    call dep_print_milli        ; imprime "X.YYY"

    lea  rdi, [rel ansi_reset]
    call io_print_string

    lea  rdi, [rel str_bits]
    call io_print_string

    pop  r12                    ; restaurar callee-saved (ABI)
    pop  rbx
    ret

; ─── dep_print_milli — imprime uint64 × 1000 como "X.YYY" ───────────────────
; rdi = valor_milli
; Callee-saved empleados: rbx (no usado), r12 (parte fraccionaria)
dep_print_milli:
    push rbx
    push r12

    ; parte entera = valor_milli / 1000
    mov  rax, rdi
    xor  rdx, rdx               ; limpiar mitad alta antes de DIV (requerido)
    mov  rcx, 1000
    div  rcx                    ; rax = entera, rdx = fracción (0..999)
    mov  r12, rdx               ; preservar fracción en callee-saved

    mov  rdi, rax
    call io_print_uint64        ; imprimir parte entera

    lea  rdi, [rel str_dot]
    call io_print_string        ; "."

    ; imprimir fracción con ceros iniciales si es necesario
    cmp  r12, 100
    jge  .pm_no_pad             ; ≥ 100: sin relleno
    cmp  r12, 10
    jge  .pm_one_zero           ; 10..99: un cero inicial

    lea  rdi, [rel str_zero2]   ; 0..9: dos ceros iniciales
    call io_print_string
    jmp  .pm_frac

.pm_one_zero:
    lea  rdi, [rel str_zero1]
    call io_print_string

.pm_no_pad:
.pm_frac:
    mov  rdi, r12
    call io_print_uint64        ; dígitos fraccionarios

    pop  r12
    pop  rbx
    ret

; =============================================================================
; display_histogram — Histograma ASCII de distribución de bytes
; =============================================================================
; void display_histogram(uint64_t *frequency_table, uint64_t total)
;   rdi = puntero a tabla de 256 qwords
;   rsi = total de bytes procesados
;
; Convención de llamada: System V AMD64 ABI
;   Callee-saved empleados:
;     rbx = freq_table pointer
;     rbp = bar_len de la fila actual
;     r12 = total bytes (no usado en bucle, reservado)
;     r13 = max_freq (referencia para escala de barras)
;     r14 = índice de byte (0..255)
;     r15 = freq del byte actual
display_histogram:
    push rbx                    ; preservar callee-saved (ABI)
    push rbp
    push r12
    push r13
    push r14
    push r15

    mov  rbx, rdi               ; rbx = freq_table
    mov  r12, rsi               ; r12 = total

    lea  rdi, [rel str_hist_title]
    call io_print_string        ; imprimir encabezado en negrita

    ; ── primera pasada: encontrar frecuencia máxima ───────────────────────────
    xor  r13, r13               ; r13 = max_freq = 0
    xor  rcx, rcx               ; índice 0..255
.dh_max:
    cmp  rcx, 256
    je   .dh_max_done
    mov  rax, [rbx + rcx*8]    ; leer freq[rcx]
    cmp  rax, r13
    jle  .dh_max_next
    mov  r13, rax               ; actualizar máximo
.dh_max_next:
    inc  rcx
    jmp  .dh_max

.dh_max_done:
    test r13, r13               ; ¿tabla completamente vacía?
    jnz  .dh_print_hdr
    lea  rdi, [rel str_no_data]
    call io_print_string
    jmp  .dh_exit               ; nada que mostrar

.dh_print_hdr:
    lea  rdi, [rel str_hist_hdr]
    call io_print_string

    ; ── segunda pasada: imprimir filas ────────────────────────────────────────
    xor  r14, r14               ; r14 = índice byte (0..255)

.dh_row:
    cmp  r14, 256
    je   .dh_exit               ; todos los bytes procesados

    mov  r15, [rbx + r14*8]    ; r15 = freq[r14]
    test r15, r15
    jz   .dh_skip               ; omitir byte con frecuencia cero

    ; ── etiqueta del byte: "  0xNN" ──────────────────────────────────────────
    lea  rdi, [rel str_0x]
    call io_print_string

    mov  rdi, r14               ; rdi = byte index (0..255)
    call dh_print_hex2          ; imprime 2 dígitos hex (sin "0x")

    lea  rdi, [rel str_two_sp]
    call io_print_string        ; separador hacia la barra

    ; ── calcular bar_len = (freq × BAR_MAX) / max_freq ───────────────────────
    ; mul produce rdx:rax (128 bits); div lo usa completo → sin overflow
    mov  rax, r15               ; rax = freq
    mov  rcx, BAR_MAX           ; rcx = 40
    mul  rcx                    ; rdx:rax = freq × 40 (mul destruye rdx)
    div  r13                    ; rax = bar_len; rdx:rax / max_freq
    test rax, rax
    jnz  .dh_bar_ok
    mov  rax, 1                 ; mínimo 1 columna si freq > 0
.dh_bar_ok:
    mov  rbp, rax               ; rbp = bar_len (callee-saved: sobrevive calls)

    ; ── llenar bar_buf con '#' × bar_len ─────────────────────────────────────
    lea  rdi, [rel bar_buf]
    mov  al,  '#'
    mov  rcx, rbp
    rep  stosb

    ; ── imprimir: cyan + barra + reset ───────────────────────────────────────
    lea  rdi, [rel ansi_cyan]
    call io_print_string        ; activar color cian

    lea  rdi, [rel bar_buf]
    mov  rsi, rbp               ; rsi = bar_len (rbp sobrevivió a io_print_string)
    call io_print_len           ; escribir bar_len bytes del buffer

    lea  rdi, [rel ansi_reset]
    call io_print_string        ; restaurar color

    ; ── relleno de espacios hasta BAR_MAX ────────────────────────────────────
    mov  rcx, BAR_MAX
    sub  rcx, rbp               ; rcx = pad count (BAR_MAX - bar_len)
    jz   .dh_no_pad

    lea  rdi, [rel bar_buf]
    mov  al,  ' '
    push rcx                    ; guardar count (rep stosb lo pone a cero)
    rep  stosb
    lea  rdi, [rel bar_buf]
    pop  rsi                    ; rsi = pad count
    call io_print_len

.dh_no_pad:
    ; ── conteo de la fila ─────────────────────────────────────────────────────
    lea  rdi, [rel str_row_end]
    call io_print_string        ; "  " separador antes del número

    mov  rdi, r15               ; r15 = freq (callee-saved, aún válido)
    call io_print_uint64        ; número en decimal

    lea  rdi, [rel str_nl]
    call io_print_string        ; '\n'

.dh_skip:
    inc  r14
    jmp  .dh_row

.dh_exit:
    pop  r15                    ; restaurar callee-saved (ABI, orden inverso)
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; ─── dh_print_hex2 — imprime byte en rdi como 2 dígitos hex ASCII ────────────
; rdi = byte value (0..255); modifica rax, rdi, rsi, rdx (caller-saved)
dh_print_hex2:
    lea  rsi, [rel dh_hex2]     ; rsi = &dh_hex2 (buffer de 2 bytes)

    ; nibble alto: (rdi >> 4) & 0xF
    mov  rax, rdi
    shr  rax, 4
    and  al,  0x0F
    cmp  al,  9
    jle  .h2_high_dec
    add  al,  'a' - 10          ; dígito hex a..f
    jmp  .h2_high_store
.h2_high_dec:
    add  al,  '0'               ; dígito 0..9
.h2_high_store:
    mov  [rsi], al

    ; nibble bajo: rdi & 0xF
    mov  rax, rdi
    and  al,  0x0F
    cmp  al,  9
    jle  .h2_low_dec
    add  al,  'a' - 10
    jmp  .h2_low_store
.h2_low_dec:
    add  al,  '0'
.h2_low_store:
    mov  [rsi + 1], al

    ; syscall write(STDOUT, dh_hex2, 2)
    mov  rdi, STDOUT
    mov  rdx, 2
    mov  rax, SYS_WRITE
    syscall
    ret

; =============================================================================
; display_error — escribe mensaje de error en stderr
; =============================================================================
; void display_error(const char *message, uint64_t length)
;   rdi = puntero al mensaje
;   rsi = longitud en bytes
display_error:
    mov  rdx, rsi               ; rdx = longitud (3.er arg syscall)
    mov  rsi, rdi               ; rsi = buffer  (2.o arg syscall)
    mov  rdi, STDERR            ; rdi = fd stderr
    call sys_write
    ret
