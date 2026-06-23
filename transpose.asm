; =============================================================================
; Archivo:     transpose.asm
; Proyecto:    Cifrador/Descifrador con Análisis de Entropía de Shannon
; Asignatura:  Taller de Programación en Bajo Nivel
; Universidad: UMSS — Facultad de Ciencias y Tecnología
; Autor(es):   [Nombre Apellido]
; Fecha:       [DD/MM/AAAA]
; Descripción: Transposición reversible de bytes mediante BSWAP (auto-inversa).
; =============================================================================
;
; PRINCIPIO DE LA TRANSPOSICIÓN:
;   BSWAP invierte el orden de los 8 bytes de un registro de 64 bits:
;     byte0 byte1 byte2 byte3 byte4 byte5 byte6 byte7
;       →   byte7 byte6 byte5 byte4 byte3 byte2 byte1 byte0
;
;   Al ser auto-inversa (BSWAP·BSWAP = identidad), la misma operación sirve
;   para cifrar y descifrar.  transpose_encrypt y transpose_decrypt son
;   idénticas y comparten la misma implementación interna.
;
;   Bytes residuales (0..7 al final del buffer):
;     Se mezclan byte a byte con su espejo dentro del residuo usando XOR.
;     P.ej. para 3 residuos [a, b, c]: resultado = [c, b, a] (mismo efecto
;     que BSWAP sobre los bytes significativos).
;     Esta operación también es auto-inversa.
;
; CONVENCIÓN DE LLAMADA: System V AMD64 ABI
;   rdi = puntero al buffer (modificado in-place)
;   rsi = longitud en bytes
; =============================================================================

global transpose_encrypt
global transpose_decrypt

; =============================================================================
section .text
; =============================================================================

; =============================================================================
; transpose_encrypt — transposición BSWAP in-place (cifrado)
; =============================================================================
; void transpose_encrypt(uint8_t *buffer, uint64_t length)
;   rdi = puntero al buffer
;   rsi = longitud en bytes
transpose_encrypt:
    jmp  tp_bswap_inplace       ; idéntica a transpose_decrypt

; =============================================================================
; transpose_decrypt — transposición BSWAP in-place (descifrado)
; =============================================================================
; void transpose_decrypt(uint8_t *buffer, uint64_t length)
;   rdi = puntero al buffer
;   rsi = longitud en bytes
transpose_decrypt:
    ; cae directamente a tp_bswap_inplace (auto-inversa)

; ─── tp_bswap_inplace — implementación compartida ────────────────────────────
; rdi = buffer, rsi = length
tp_bswap_inplace:
    test rsi, rsi               ; ¿longitud == 0?
    jz   .tp_done               ; sí → nada que hacer

    ; ── FASE 1: bloques completos de 8 bytes ─────────────────────────────────
    mov  rcx, rsi
    shr  rcx, 3                 ; rcx = length / 8  (bloques completos)
    jz   .tp_residual           ; 0 bloques → ir directo a residuos

.tp_block_loop:
    mov  rax, [rdi]             ; cargar 8 bytes en rax
    bswap rax                   ; invertir orden de bytes dentro del qword
    mov  [rdi], rax             ; guardar resultado en el mismo lugar

    add  rdi, 8                 ; avanzar puntero al siguiente bloque
    dec  rcx
    jnz  .tp_block_loop         ; repetir si quedan bloques

    ; ── FASE 2: bytes residuales (0..7 bytes al final) ───────────────────────
    ; Se intercambian byte a byte usando dos punteros: izq (rdi) y der (rbx).
    ; La condición de parada es rdi < rbx; si son iguales o se cruzan, listo.
.tp_residual:
    mov  rcx, rsi
    and  rcx, 7                 ; rcx = length % 8  (0..7 residuos)
    jz   .tp_done               ; sin residuos

    ; rdi ya apunta al primer byte residual (avanzó en la fase 1)
    push rbx                    ; preservar registro callee-saved (ABI)

    lea  rbx, [rdi + rcx - 1]  ; rbx = puntero al último byte residual

.tp_swap_loop:
    cmp  rdi, rbx               ; ¿punteros se cruzaron o coinciden?
    jge  .tp_swap_done          ; sí → fin del intercambio

    movzx rax, byte [rdi]       ; al = byte izquierdo
    movzx rdx, byte [rbx]       ; dl = byte derecho

    mov  [rdi], dl              ; intercambiar
    mov  [rbx], al

    inc  rdi                    ; avanzar puntero izquierdo
    dec  rbx                    ; retroceder puntero derecho
    jmp  .tp_swap_loop

.tp_swap_done:
    pop  rbx                    ; restaurar callee-saved (ABI)

.tp_done:
    ret
