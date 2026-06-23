; =============================================================================
; cipher.asm — Cifrado/Descifrado XOR por bloques de 64 bits
; Proyecto: Cifrador/Descifrador con Análisis de Entropía de Shannon
; =============================================================================
;
; PRINCIPIO DEL XOR:
;   Cifrado:    C = P XOR K   (plaintext XOR key  = ciphertext)
;   Descifrado: P = C XOR K   (ciphertext XOR key = plaintext)
;   La operación es IDÉNTICA en ambos sentidos → una sola función sirve para
;   cifrar y descifrar.
;
; ESTRATEGIA DE BLOQUES:
;   ┌─────────────────────────────────────────────┐
;   │  buffer   [0..7] [8..15] [16..23] … [n-r..n-1]  │
;   │            bloque bloque  bloque    residuo       │
;   └─────────────────────────────────────────────┘
;   • Cada bloque completo de 8 bytes (64 bits) se procesa con un único
;     MOV de 64 bits + XOR de 64 bits → muy eficiente.
;   • Los bytes residuales (0 a 7) se procesan byte a byte con el byte
;     de la clave en la posición correspondiente (key_byte[i % 8]).
;
; EXPANSIÓN DE CLAVE:
;   La clave recibida es un puntero a una cadena ASCII (p.ej. "miClave123").
;   Para obtener una clave de 64 bits se mezclan hasta 8 bytes de la cadena:
;     key64 = byte[0] | byte[1]<<8 | byte[2]<<16 | … (little-endian)
;   Si la cadena tiene menos de 8 bytes, los bytes faltantes son 0.
;   La clave resultante se almacena en la variable local key64 (sección .bss).
;
; CONVENCIÓN DE LLAMADA: System V AMD64 ABI
;   Argumentos:    rdi, rsi, rdx, rcx, r8, r9
;   Retorno:       rax
;   Callee-saved:  rbx, rbp, r12, r13, r14, r15
; =============================================================================

global cipher_xor
global cipher_build_key64

section .bss
    key64 resq 1                ; clave de 64 bits construida desde ASCII

section .text

; =============================================================================
; cipher_build_key64 — Convierte una cadena ASCII en una clave de 64 bits
; =============================================================================
; uint64_t cipher_build_key64(const char *key_str)
;   rdi = puntero a la cadena clave (null-terminated)
;   rax = clave de 64 bits (también guardada en key64 global)
;
; La clave se almacena en la variable global key64.
; Mezcla hasta los primeros 8 bytes de la cadena en little-endian.
; Bytes faltantes (cadena corta) contribuyen con 0.
;
; Si la clave es vacía o nula se almacena 0, lo que produce un XOR
; con 0 (cifrado nulo).  El llamador debe validar antes.
;
; Registros internos:
;   rbx = puntero a key_str (callee-saved)
;   r12 = acumulador de la clave de 64 bits
;   r13 = índice del byte actual (0..7) — callee-saved; libera rcx para SHL
;   rcx = desplazamiento en bits (i*8); SHL variable requiere CL obligatoriamente
;   al  = byte leído de la cadena
;
; NOTA: el índice debe estar en r13 (no en rcx) porque SHL con conteo variable
; exige que el conteo esté en CL (byte bajo de RCX).  Si rcx fuese el índice
; i, SHL usaría i como desplazamiento en vez del correcto i*8.
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
; cipher_xor — Cifra/Descifra un buffer en memoria usando XOR de 64 bits
; =============================================================================
; void cipher_xor(uint8_t *buffer, uint64_t length, uint64_t key)
;   rdi = puntero al buffer (modificado IN PLACE)
;   rsi = longitud en bytes
;   rdx = clave de 64 bits
;
; El buffer se modifica directamente (cifrado en sitio).
; Para descifrar: llamar con los mismos argumentos sobre el buffer cifrado.
;
; FASE 1 — Bloques completos de 8 bytes:
;   • Bucle de (length / 8) iteraciones.
;   • Cada iteración: MOV QWORD + XOR QWORD + MOV QWORD.
;   • Se usan registros de 64 bits para máximo rendimiento.
;
; FASE 2 — Bytes residuales (length % 8):
;   • Bucle de 0 a 7 iteraciones.
;   • El byte de clave para la posición i es (key >> (i*8)) & 0xFF.
;
; Registros internos:
;   rdi = cursor al buffer (avanza 8 bytes por bloque)
;   rsi = bytes restantes (cuenta regresiva)
;   rdx = clave de 64 bits (constante durante todo el bucle)
;   rax = bloque de 8 bytes leído del buffer
;   r8  = byte individual de clave extraído para residuos
;   rcx = contador de bytes residuales
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
