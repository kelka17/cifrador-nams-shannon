; =============================================================================
; Archivo:     include/macros.inc
; Proyecto:    Cifrador/Descifrador con Análisis de Entropía de Shannon
; Asignatura:  Taller de Programación en Bajo Nivel
; Universidad: UMSS — Facultad de Ciencias y Tecnología
; Descripción: Macros de pipeline: EXIT, WRITE, CIFRAR_BLOQUE y variantes.
; =============================================================================
;
; ==============================================================================
; MÓDULO 1 — PIPELINE DE CIFRADO/DESCIFRADO
; ==============================================================================
;
;   El cifrador aplica dos transformaciones en cadena:
;
;   CIFRADO:
;     1. cipher_xor(buf, len, key)   — difusión algebraica (XOR con clave)
;     2. transpose_encrypt(buf, len) — difusión espacial  (permutación BSWAP)
;
;   Ciphertext = BSWAP( XOR(Plaintext, K) )
;
;   DESCIFRADO (orden inverso de las transformaciones):
;     1. transpose_decrypt(buf, len) — inversa de BSWAP (auto-inversa: BSWAP)
;     2. cipher_xor(buf, len, key)   — inversa de XOR  (auto-inversa: XOR)
;
;   Plaintext = XOR( BSWAP(Ciphertext), K )
;
;   DEMOSTRACIÓN DE CORRECCIÓN DEL ROUND-TRIP:
;     Sea C = BSWAP(XOR(P, K))
;     Descifrar(C) = XOR(BSWAP(C), K)
;                 = XOR(BSWAP(BSWAP(XOR(P,K))), K)
;                 = XOR(XOR(P,K), K)          [BSWAP⁻¹ = BSWAP]
;                 = P XOR K XOR K              [XOR⁻¹ = XOR]
;                 = P XOR 0                    [a XOR a = 0]
;                 = P                          ✓
;
; ==============================================================================
; MÓDULO 2 — RESTRICCIONES DE LOS ARGUMENTOS DE MACRO
; ==============================================================================
;
;   %1 = buffer (puntero):
;     Debe ser una referencia a memoria ([rel var]) o un registro callee-saved
;     (r12..r15, rbx, rbp). Esto es necesario porque las macros llaman a
;     funciones que destruyen los registros caller-saved (rdi, rsi, rax…).
;
;   %2 = length (longitud en bytes):
;     Ídem: referencia a memoria o registro callee-saved.
;
;   %3 = key_str (clave ASCII):
;     Puede ser una etiqueta RIP-relativa o un registro con el puntero.
;
;   EJEMPLO CORRECTO (callee-saved):
;     CIFRAR_BLOQUE r12, r13, key_str   ; r12 y r13 sobreviven las calls
;
;   EJEMPLO CORRECTO (memoria):
;     CIFRAR_BLOQUE [rel buf_ptr], [rel file_size], key_str
;
;   EJEMPLO INCORRECTO (caller-saved):
;     CIFRAR_BLOQUE rdi, rsi, key_str   ; rdi/rsi destruidos por cipher_build_key64
;
; ==============================================================================
; MÓDULO 3 — TABLA RESUMEN DE MACROS
; ==============================================================================
;
;   MACRO              ARGS              OPERACIÓN                  USO
;   ─────────────────────────────────────────────────────────────────────────
;   EXIT code          code              exit(code)                 salida
;   WRITE fd,buf,len   fd,buf,len        sys_write(fd,buf,len)      I/O
;   CIFRAR_BLOQUE      buf,len,key       XOR(buf,len,key)           cifrado XOR
;   DESCIFRAR_BLOQUE   buf,len,key       XOR(buf,len,key)           descifrado XOR
;   CIFRAR_COMPLETO    buf,len,key       XOR then BSWAP             cifrado full
;   DESCIFRAR_COMPLETO buf,len,key       BSWAP then XOR             descifrado full
;
; =============================================================================

%ifndef MACROS_INC
%define MACROS_INC

; EXIT code — termina el proceso con código de salida dado
%macro EXIT 1
    mov rdi, %1
    call sys_exit
%endmacro

; WRITE fd, buf, len — escribe len bytes de buf en fd
%macro WRITE 3
    mov rdi, %1
    mov rsi, %2
    mov rdx, %3
    call sys_write
%endmacro

; =============================================================================
; CIFRAR_BLOQUE buf, len, key_str
; =============================================================================
; Aplica cifrado XOR de 64 bits in-place (sin transposición).
;
; Equivalente formal:  buf = XOR(buf, len, cipher_build_key64(key_str))
;
; Precondición: %1/%2 son callee-saved o referencias a memoria.
; Postcondición: buf[i] = buf[i] XOR K[i mod 8]  ∀ i ∈ [0, len)
;
; Funciona para CUALQUIER tamaño:
;   • Bloques completos (len / 8): procesados con XOR de 64 bits.
;   • Residuo (len mod 8, 0..7 bytes): procesados byte a byte.
; Esto la hace reutilizable para distintos tamaños de bloque sin modificación.
;
; Nota: XOR es auto-inversa (XOR(XOR(P,K),K) = P), por lo que esta macro
; sirve tanto para cifrar como para descifrar. Ver DESCIFRAR_BLOQUE.
%macro CIFRAR_BLOQUE 3
    mov  rdi, %3
    call cipher_build_key64     ; rax = key64 (cipher_xor no modifica rdx)
    mov  rdx, rax               ; rdx = key64 (sobrevive a las movs de %1/%2)
    mov  rdi, %1                ; buffer (callee-saved o mem-ref)
    mov  rsi, %2                ; longitud (callee-saved o mem-ref)
    call cipher_xor             ; XOR in-place con rdx=clave
%endmacro

; =============================================================================
; DESCIFRAR_BLOQUE buf, len, key_str
; =============================================================================
; Alias semántico de CIFRAR_BLOQUE: la operación XOR es su propia inversa.
;
; Equivalente formal:  XOR(XOR(P, K), K) = P
; Por lo tanto:        DESCIFRAR_BLOQUE ≡ CIFRAR_BLOQUE  (misma operación)
;
; Se define como macro separada para claridad semántica en el código llamante.
%macro DESCIFRAR_BLOQUE 3
    CIFRAR_BLOQUE %1, %2, %3
%endmacro

; =============================================================================
; CIFRAR_COMPLETO buf, len, key_str
; =============================================================================
; Pipeline de cifrado completo: XOR seguido de transposición BSWAP.
;
;   Ciphertext = BSWAP( XOR(Plaintext, key64) )
;
; Precondición: %1/%2 son callee-saved o referencias a memoria.
;
; Implementación:
;   1. cipher_build_key64(key_str) → key64 en rax → guardado en rdx
;      (cipher_xor no modifica rdx → rdx sigue siendo key64 después del XOR)
;   2. cipher_xor(buf, len, key64) → XOR in-place
;   3. transpose_encrypt(buf, len) → BSWAP in-place
;      (se recarga %1/%2 porque cipher_xor avanzó rdi)
%macro CIFRAR_COMPLETO 3
    mov  rdi, %3
    call cipher_build_key64     ; rax = key64; rdx libre
    mov  rdx, rax               ; rdx = key64 (cipher_xor preserva rdx)
    mov  rdi, %1
    mov  rsi, %2
    call cipher_xor             ; XOR in-place (rdx=key64 preservado)
    mov  rdi, %1                ; recargar: cipher_xor avanzó rdi
    mov  rsi, %2
    call transpose_encrypt      ; BSWAP in-place
%endmacro

; =============================================================================
; DESCIFRAR_COMPLETO buf, len, key_str
; =============================================================================
; Pipeline de descifrado completo: transposición BSWAP seguida de XOR.
; Orden inverso al cifrado: BSWAP⁻¹ primero, luego XOR⁻¹.
;
;   Plaintext = XOR( BSWAP(Ciphertext), key64 )
;
; Demostración de corrección (ver MÓDULO 1):
;   DESCIFRAR_COMPLETO( CIFRAR_COMPLETO(P, K) ) = P  ✓
;
; Implementación:
;   1. transpose_decrypt(buf, len) → BSWAP inverso (idéntico a encrypt)
;      (BSWAP es auto-inversa: BSWAP(BSWAP(x)) = x)
;   2. cipher_build_key64(key_str) → key64
;      (construir la clave DESPUÉS del transpose para evitar que transpose
;       clobber rdx, donde guardamos key64 para el XOR)
;   3. cipher_xor(buf, len, key64) → XOR in-place
%macro DESCIFRAR_COMPLETO 3
    mov  rdi, %1
    mov  rsi, %2
    call transpose_decrypt      ; BSWAP inverso (transpose usa rdx — no guardar key aquí)
    mov  rdi, %3
    call cipher_build_key64     ; rax = key64 (construir DESPUÉS del transpose)
    mov  rdi, %1
    mov  rsi, %2
    mov  rdx, rax               ; rdx = key64
    call cipher_xor             ; XOR in-place
%endmacro

%endif
