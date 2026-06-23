; =============================================================================
; cipher.asm — Cifrado/Descifrado XOR por bloques de 64 bits
; Proyecto:    Cifrador/Descifrador con Análisis de Entropía de Shannon
; Asignatura:  Taller de Programación en Bajo Nivel
; Universidad: UMSS — Facultad de Ciencias y Tecnología
; =============================================================================
;
; ─────────────────────────────────────────────────────────────────────────────
; 1. DEFINICIÓN FORMAL DEL CIFRADO
; ─────────────────────────────────────────────────────────────────────────────
;
;   Sea P = (P[0], P[1], …, P[n-1])  el texto plano  de n bytes.
;   Sea K = (K[0], K[1], …, K[7])    la clave de 8 bytes (key64).
;   Sea C = (C[0], C[1], …, C[n-1])  el texto cifrado de n bytes.
;
;   Cifrado:    C[i] = P[i] ⊕ K[i mod 8]   para todo i ∈ [0, n-1]
;   Descifrado: P[i] = C[i] ⊕ K[i mod 8]   para todo i ∈ [0, n-1]
;
;   Ambas operaciones son IDÉNTICAS porque ⊕ es auto-inverso:
;     C[i] ⊕ K[i mod 8] = P[i] ⊕ K[i mod 8] ⊕ K[i mod 8] = P[i] ⊕ 0 = P[i]
;
; ─────────────────────────────────────────────────────────────────────────────
; 2. ESTRATEGIA DE IMPLEMENTACIÓN: BLOQUES + RESIDUO
; ─────────────────────────────────────────────────────────────────────────────
;
;   Sea q = ⌊n / 8⌋  (bloques completos)   y   r = n mod 8  (bytes residuales).
;
;   ┌──────────────┬──────────────┬─────┬──────────┐
;   │  bloque 0    │  bloque 1    │ … │  residuo  │
;   │  P[0..7]     │  P[8..15]    │   │ P[8q..n-1]│
;   └──────────────┴──────────────┴─────┴──────────┘
;   └────────────── q bloques de 8 bytes ──────────┘└── r bytes ─┘
;
;   FASE 1 — Bloques completos (i ∈ [0, q-1]):
;     Se carga un QWORD (8 bytes) en rax, se aplica XOR con key64 completo
;     en una sola instrucción de 64 bits, y se escribe de vuelta.
;     Coste: 3 accesos a memoria + 1 XOR por bloque → O(n/8).
;
;   FASE 2 — Bytes residuales (j ∈ [0, r-1]):
;     Cada byte P[8q + j] se cifra con K[j mod 8] = (key64 >> (j×8)) & 0xFF.
;     Como j ∈ [0, 7] y r = n mod 8 ∈ [0, 7], j < 8 siempre, por lo que
;     j mod 8 = j. No hay desbordamiento del registro de 64 bits.
;     Coste: 1 acceso a memoria + 1 SHR + 1 XOR por byte residual → O(r) ≤ O(7).
;
;   Complejidad total: O(n) tiempo, O(1) espacio adicional.
;
; ─────────────────────────────────────────────────────────────────────────────
; 3. CONSTRUCCIÓN DE LA CLAVE (cipher_build_key64)
; ─────────────────────────────────────────────────────────────────────────────
;
;   Dado un string ASCII s de longitud L:
;     key64 = ∑ s[i] × 2^(8i)   para i ∈ [0, min(L,8)-1]   (little-endian)
;
;   Si L < 8, los bytes faltantes contribuyen con 0 → key64 tiene bytes nulos
;   en las posiciones superiores. La clave se trunca a 8 bytes si L > 8.
;
; ─────────────────────────────────────────────────────────────────────────────
; 4. CONVENCIÓN DE LLAMADA: System V AMD64 ABI
; ─────────────────────────────────────────────────────────────────────────────
;
;   Paso de argumentos:  rdi, rsi, rdx, rcx, r8, r9
;   Valor de retorno:    rax
;   Callee-saved:        rbx, rbp, r12, r13, r14, r15
;   Caller-saved:        rax, rcx, rdx, rsi, rdi, r8, r9, r10, r11
;
; =============================================================================

global cipher_xor
global cipher_build_key64

section .bss
    key64 resq 1                ; clave de 64 bits construida desde ASCII

section .text

; =============================================================================
; cipher_build_key64 — Construye la clave de 64 bits desde una cadena ASCII
; =============================================================================
; uint64_t cipher_build_key64(const char *key_str)
;   Precondición:  rdi apunta a una cadena null-terminated válida (puede ser "").
;   Postcondición: rax = key64 = ∑ s[i]×2^(8i) para i ∈ [0,min(|s|,8)-1].
;                  La variable global key64 contiene el mismo valor.
;
; RESTRICCIÓN DE ARQUITECTURA — por qué el índice NO puede estar en rcx:
;   La instrucción SHL reg, cl requiere que el conteo esté en CL (bits 7..0
;   de RCX). Si rcx == i, entonces cl == i, y SHL calcularía byte << i en
;   lugar de byte << (i×8). Por eso el índice i está en r13 (callee-saved)
;   y rcx sólo almacena el desplazamiento en bits (i×8).
;
; TABLA DE REGISTROS:
;   rbx  callee-saved  puntero base a key_str
;   r12  callee-saved  acumulador de key64
;   r13  callee-saved  índice i ∈ [0, 7]
;   rcx  caller-saved  desplazamiento en bits = i×8  (para SHL)
;   rax  caller-saved  byte leído y desplazado temporalmente
;
; INVARIANTE DE BUCLE (al inicio de cada iteración):
;   r12 = ∑ s[j]×2^(8j)  para j ∈ [0, r13-1]
;   r13 ∈ [0, 8]
;   Si r13 == 0, r12 == 0 (acumulador vacío).
cipher_build_key64:
    push rbx                    ; preservar callee-saved (ABI)
    push r12
    push r13

    mov  rbx, rdi               ; rbx = puntero a la cadena clave
    xor  r12, r12               ; r12 = acumulador de clave = 0
    xor  r13, r13               ; r13 = índice i = 0

.bk_loop:
    cmp  r13, 8                 ; ¿ya procesamos 8 bytes?
    jge  .bk_done

    movzx rax, byte [rbx + r13] ; leer byte[i]; zero-extend a 64 bits
    test  al, al                 ; ¿null terminator?
    jz    .bk_done               ; sí → cadena más corta que 8 bytes

    ; colocar el byte en su posición little-endian: byte[i] << (i×8)
    mov  rcx, r13
    shl  rcx, 3                 ; rcx = i × 8  (desplazamiento en bits)
    shl  rax, cl                ; rax = byte << (i×8)  ✓  [cl = rcx & 0xFF = i×8]
    or   r12, rax               ; acumular en la clave de 64 bits

    inc  r13
    jmp  .bk_loop

.bk_done:
    ; guardar clave de 64 bits en variable global key64
    lea  rax, [rel key64]
    mov  [rax], r12

    mov  rax, r12               ; retornar clave en rax (antes de pop r12)

    pop  r13                    ; restaurar callee-saved (ABI, orden inverso)
    pop  r12
    pop  rbx
    ret

; =============================================================================
; cipher_xor — Aplica el cifrado XOR stream sobre un buffer en memoria
; =============================================================================
; void cipher_xor(uint8_t *buffer, uint64_t length, uint64_t key64)
;   Precondición:  rdi apunta a un buffer de al menos 'length' bytes.
;                  rsi = length ≥ 0.
;                  rdx = key64 ≠ 0 (si key64 == 0, la función retorna sin cambios).
;   Postcondición: buffer[i] = buffer_in[i] ⊕ K[i mod 8]  para i ∈ [0, length-1]
;                  donde K[j] = (key64 >> (j×8)) & 0xFF.
;
; TABLA DE REGISTROS — cipher_xor:
;   rdi  caller-saved  cursor al buffer (avanza 8B por bloque, 1B por residuo)
;   rsi  caller-saved  longitud en bytes (se preserva para calcular residuo)
;   rdx  caller-saved  key64, constante durante todo el algoritmo
;   rcx  caller-saved  FASE 1: contador de bloques; FASE 2: desplazamiento de bits
;   rax  caller-saved  bloque de 8 bytes leído (FASE 1) / byte de clave (FASE 2)
;   rbx  callee-saved  copia de key64 en FASE 2 (libera rdx si fuese necesario)
;   r9   caller-saved  contador de bytes residuales en FASE 2
;   r10  caller-saved  acumulador de desplazamiento en bits (0, 8, 16, …) en FASE 2
;
; NOTA DE ARQUITECTURA — por qué r9/r10 y no un solo rcx:
;   SHR reg, cl requiere el conteo en CL. Si rcx actuara como contador de bytes
;   residuales, no podría usarse simultáneamente como desplazamiento para SHR.
;   La solución: r9 = contador de iteraciones, r10 = desplazamiento acumulado,
;   y rcx se carga desde r10 justo antes de cada SHR.
;
; INVARIANTE FASE 1 (al inicio de cada iteración del bloque):
;   rdi apunta a buffer[8k], donde k es el número de bloques ya procesados.
;   rcx es el número de bloques PENDIENTES.
;   buffer[0..8k-1] ya ha sido correctamente cifrado.
;
; INVARIANTE FASE 2 (al inicio de cada iteración del residuo):
;   rdi apunta a buffer[8q + j], donde q = ⌊length/8⌋ y j es el número de
;   bytes residuales ya procesados.
;   r9 es el número de bytes residuales PENDIENTES.
;   r10 = j × 8 (desplazamiento para obtener K[j] de key64).
;   buffer[0..8q+j-1] ya ha sido correctamente cifrado.
cipher_xor:
    ; ── validaciones rápidas ─────────────────────────────────────────────────
    test rsi, rsi               ; length == 0?
    jz   .cx_done
    test rdx, rdx               ; key == 0? (XOR con 0 no cifra nada)
    jz   .cx_done               ; permitir pero no hace nada útil

    ; ── FASE 1: bloques de 64 bits ───────────────────────────────────────────
    ; rcx = número de bloques completos = length >> 3
    mov  rcx, rsi
    shr  rcx, 3                 ; rcx = length / 8
    jz   .cx_residual           ; si 0 bloques completos → ir a residuos

.cx_block_loop:
    ; Leer 8 bytes del buffer, XOR con clave, escribir de vuelta
    ;
    ;   mov rax, [rdi]   → carga 8 bytes (little-endian) en rax
    ;   xor rax, rdx     → aplica XOR con la clave de 64 bits
    ;   mov [rdi], rax   → guarda el resultado en el mismo lugar
    ;
    mov  rax, [rdi]             ; cargar bloque de 8 bytes
    xor  rax, rdx               ; XOR con clave completa
    mov  [rdi], rax             ; guardar bloque cifrado

    add  rdi, 8                 ; avanzar puntero 8 bytes
    dec  rcx
    jnz  .cx_block_loop         ; repetir si quedan bloques

    ; ── FASE 2: bytes residuales ─────────────────────────────────────────────
    ; rsi aún tiene la longitud original; calcular residuo
.cx_residual:
    mov  rcx, rsi
    and  rcx, 7                 ; rcx = length % 8  (bytes sobrantes: 0..7)
    jz   .cx_done               ; sin residuos → terminar

    ; Para cada byte residual en posición i:
    ;   key_byte = (key >> (i * 8)) & 0xFF
    ; x86-64 sólo permite cl como registro de desplazamiento variable en SHR.
    ; Usamos r9 como contador y r10 como acumulador de bits de desplazamiento.
    push rbx
    mov  rbx, rdx               ; rbx = clave (callee-saved)
    mov  r9,  rcx               ; r9  = número de bytes residuales
    xor  r10, r10               ; r10 = bits de desplazamiento (0, 8, 16…)

.cx_byte_loop:
    mov  rcx, r10               ; mover desplazamiento a rcx (cl requerido por SHR)
    mov  rax, rbx
    shr  rax, cl                ; rax = key >> (i*8)
    and  al, 0xFF               ; aislar byte de clave

    xor  [rdi], al              ; XOR byte a byte
    inc  rdi

    add  r10, 8                 ; siguiente byte de la clave
    dec  r9
    jnz  .cx_byte_loop

    pop  rbx

.cx_done:
    ret
