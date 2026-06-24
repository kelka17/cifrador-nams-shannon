; =============================================================================
; Archivo:     transpose.asm
; Proyecto:    Cifrador/Descifrador con Análisis de Entropía de Shannon
; Asignatura:  Taller de Programación en Bajo Nivel
; Universidad: UMSS — Facultad de Ciencias y Tecnología
; =============================================================================
;
; ─────────────────────────────────────────────────────────────────────────────
; 1. PROPÓSITO CRIPTOGRÁFICO: DIFUSIÓN
; ─────────────────────────────────────────────────────────────────────────────
;
;   El cifrado XOR stream solo produce "confusión" (cada byte de salida depende
;   de un único byte de la clave), pero no "difusión" (C. Shannon, 1949):
;   un cambio en un bit de plaintext afecta exactamente un bit de ciphertext.
;
;   La transposición de bytes aumenta la difusión al mezclar las posiciones de
;   los bytes DENTRO de cada bloque de 8 bytes después del XOR.  Así, un bit
;   modificado en el plaintext termina en una posición distinta del bloque
;   cifrado final, dificultando el análisis estadístico.
;
; ─────────────────────────────────────────────────────────────────────────────
; 2. DEFINICIÓN FORMAL DE LA TRANSPOSICIÓN
; ─────────────────────────────────────────────────────────────────────────────
;
;   Sea B = (b₀, b₁, b₂, b₃, b₄, b₅, b₆, b₇) un bloque de 8 bytes en memoria.
;
;   Permutación de cifrado:
;     π: {0,…,7} → {0,…,7}   donde   π(i) = 7 − i
;     T(B) = (b₇, b₆, b₅, b₄, b₃, b₂, b₁, b₀)
;
;   TEOREMA (auto-inversa): T(T(B)) = B
;     Prueba: T(T(B))_i = T(B)_{π(i)} = T(B)_{7-i} = B_{π(7-i)} = B_{7-(7-i)} = B_i ∎
;
;   Para r bytes residuales (0 ≤ r ≤ 7):
;     Permutación espejo: σ: {0,…,r-1} → {0,…,r-1}   donde   σ(i) = r − 1 − i
;     TEOREMA (auto-inversa): σ(σ(i)) = σ(r-1-i) = r-1-(r-1-i) = i ∎
;
;   COROLARIO: transpose_encrypt y transpose_decrypt son IDÉNTICAS.
;     transpose_encrypt(T(B)) = T(T(B)) = B = transpose_decrypt(T(B))
;
; ─────────────────────────────────────────────────────────────────────────────
; 3. IMPLEMENTACIÓN: INSTRUCCIÓN BSWAP
; ─────────────────────────────────────────────────────────────────────────────
;
;   x86-64 provee BSWAP reg64, que invierte los 8 bytes de un registro en
;   una sola instrucción (1 micro-op, latencia 1 ciclo en CPUs modernas).
;
;   Relación entre memoria, little-endian y BSWAP:
;
;     Dirección:     buf+0  buf+1  buf+2  buf+3  buf+4  buf+5  buf+6  buf+7
;     Bytes:          b₀     b₁     b₂     b₃     b₄     b₅     b₆     b₇
;
;     MOV rax,[buf] → rax = b₇b₆b₅b₄b₃b₂b₁b₀  (b₀ en LSB, b₇ en MSB)
;     BSWAP rax     → rax = b₀b₁b₂b₃b₄b₅b₆b₇  (invierte bytes del registro)
;     MOV [buf],rax → buf = [b₇, b₆, b₅, b₄, b₃, b₂, b₁, b₀]  (b₀ queda en buf+7)
;
;   El efecto neto en memoria es exactamente la permutación π(i) = 7 − i.
;
; ─────────────────────────────────────────────────────────────────────────────
; 4. COMPLEJIDAD
; ─────────────────────────────────────────────────────────────────────────────
;
;   Sea n la longitud del buffer, q = ⌊n/8⌋ bloques, r = n mod 8 residuos.
;
;   FASE 1 (bloques): q iteraciones × O(1) = O(n/8) ⊂ O(n)
;   FASE 2 (residuo): ⌊r/2⌋ ≤ 3 iteraciones = O(1)
;   Total: O(n) tiempo, O(1) espacio adicional.
;
; ─────────────────────────────────────────────────────────────────────────────
; 5. CONVENCIÓN DE LLAMADA: System V AMD64 ABI
; ─────────────────────────────────────────────────────────────────────────────
;
;   Paso de argumentos:  rdi, rsi, rdx, rcx, r8, r9
;   Valor de retorno:    rax  (esta función retorna void)
;   Callee-saved:        rbx, rbp, r12, r13, r14, r15
;
; =============================================================================

global transpose_encrypt
global transpose_decrypt

; =============================================================================
section .text
; =============================================================================

; =============================================================================
; transpose_encrypt — permutación de bytes (cifrado, aumenta difusión)
; =============================================================================
; void transpose_encrypt(uint8_t *buffer, uint64_t length)
;   Precondición:  rdi apunta a un buffer de al menos 'length' bytes.
;                  rsi = length ≥ 0.
;   Postcondición: buffer[i] = buffer_in[π⁻¹(i)] donde π(i) = 7−i dentro de
;                  cada bloque, y σ(i)=r−1−i para los residuos finales.
;   Efecto neto:   inversión del orden de bytes por bloque (BSWAP in-place).
;
; TABLA DE REGISTROS:
;   rdi  cursor que avanza de bloque en bloque (8B/iter en FASE 1)
;   rsi  longitud total en bytes (preserved para cálculo de residuos)
;   rcx  FASE 1: contador de bloques pendientes
;   rax  bloque leído del buffer antes y después de BSWAP
;   rbx  callee-saved: puntero al extremo derecho del residuo (FASE 2)
;
; INVARIANTE FASE 1 (al inicio de cada iteración):
;   rdi = &buffer[8k], k = bloques ya transpuestos
;   rcx = q − k  (bloques pendientes, q = ⌊length/8⌋)
;   buffer[0..8k-1] ya ha sido correctamente transpuesto.
;
; INVARIANTE FASE 2 (al inicio de cada iteración):
;   rdi < rbx  (punteros sin cruzar; el cruce indica fin)
;   Los bytes en [rdi, rbx] aún no han sido intercambiados.
;   Los bytes fuera de [rdi, rbx] ya están en su posición final.
transpose_encrypt:
    jmp  tp_bswap_inplace           ; idéntica a transpose_decrypt (ver §2 corolario)

; =============================================================================
; transpose_decrypt — permutación inversa (descifrado)
; =============================================================================
; void transpose_decrypt(uint8_t *buffer, uint64_t length)
;   Precondición / Postcondición: idénticas a transpose_encrypt.
;   Corrección: como π y σ son auto-inversas (Teorema §2), aplicar la misma
;   permutación sobre el buffer transpuesto recupera el original exactamente.
;
; DEMOSTRACIÓN DE CORRECCIÓN DEL DESCIFRADO:
;   Sea B el bloque original y T = transpose_encrypt.
;   Ciframos: B' = T(B).
;   Desciframos: T(B') = T(T(B)) = B  (por auto-inversa de T).
;   Por lo tanto, transpose_decrypt ≡ transpose_encrypt. ∎
transpose_decrypt:
    ; cae a tp_bswap_inplace — la auto-inversa garantiza la corrección

; ─── tp_bswap_inplace — implementación compartida ────────────────────────────
tp_bswap_inplace:
    test rsi, rsi                   ; ¿length == 0?
    jz   .tp_done

    ; ── FASE 1: bloques completos de 8 bytes con BSWAP ───────────────────────
    ;
    ;   Por cada bloque k ∈ [0, q-1]:
    ;     rax ← MOV [buf + 8k]     (carga b₀…b₇ en little-endian)
    ;     rax ← BSWAP rax          (invierte bytes del registro)
    ;     [buf + 8k] ← rax         (guarda b₇…b₀ en memoria)
    ;
    mov  rcx, rsi
    shr  rcx, 3                     ; rcx = q = ⌊length/8⌋
    jz   .tp_residual               ; q == 0 → saltar directo a residuos

.tp_block_loop:
    mov   rax, [rdi]                ; cargar bloque de 8 bytes
    bswap rax                       ; invertir orden: b₀↔b₇, b₁↔b₆, b₂↔b₅, b₃↔b₄
    mov   [rdi], rax                ; guardar bloque transpuesto

    add  rdi, 8                     ; avanzar cursor al siguiente bloque
    dec  rcx
    jnz  .tp_block_loop

    ; ── FASE 2: r bytes residuales (intercambio espejo con dos punteros) ─────
    ;
    ;   Sea r = length mod 8.  Los bytes residuales están en [rdi, rdi+r-1].
    ;   Se usa el algoritmo de inversión con dos punteros:
    ;     izq = rdi  (avanza hacia la derecha)
    ;     der = rdi + r - 1  (retrocede hacia la izquierda)
    ;   Mientras izq < der: swap(buf[izq], buf[der]); izq++; der--
    ;
    ;   Este algoritmo implementa σ(i) = r − 1 − i en ⌊r/2⌋ pasos.
    ;   Es auto-inverso por el Teorema §2.
    ;
.tp_residual:
    mov  rcx, rsi
    and  rcx, 7                     ; rcx = r = length mod 8
    jz   .tp_done                   ; r == 0 → no hay residuos

    push rbx                        ; preservar callee-saved (ABI)
    lea  rbx, [rdi + rcx - 1]      ; rbx = puntero al último byte residual

    ; INVARIANTE: bytes en (−∞, rdi) y (rbx, +∞) ya en posición final
.tp_swap_loop:
    cmp  rdi, rbx                   ; ¿rdi >= rbx? (punteros cruzados o iguales)
    jge  .tp_swap_done

    movzx rax, byte [rdi]           ; leer byte izquierdo
    movzx rdx, byte [rbx]           ; leer byte derecho

    mov  [rdi], dl                  ; escribir derecho en posición izquierda
    mov  [rbx], al                  ; escribir izquierdo en posición derecha

    inc  rdi                        ; izq avanza
    dec  rbx                        ; der retrocede
    jmp  .tp_swap_loop

.tp_swap_done:
    pop  rbx                        ; restaurar callee-saved (ABI)

.tp_done:
    ret
