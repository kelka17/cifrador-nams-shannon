; =============================================================================
; Archivo:     include/macros.inc
; Proyecto:    Cifrador/Descifrador con Análisis de Entropía de Shannon
; Asignatura:  Taller de Programación en Bajo Nivel
; Universidad: UMSS — Facultad de Ciencias y Tecnología
; Descripción: Macros compartidas: EXIT, WRITE y CIFRAR_BLOQUE (§5.5 propuesta).
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

; CIFRAR_BLOQUE buf, len, key_str — construye clave desde ASCII y cifra in-place
; %1 = puntero al buffer (registro o referencia a memoria)
; %2 = longitud en bytes (registro o referencia a memoria)
; %3 = puntero a la cadena clave ASCII (null-terminated)
; Efecto: cipher_build_key64(%3) retorna key64 en rax; luego cipher_xor(%1, %2, rax)
; Si %1/%2 son registros callee-saved, sobreviven la llamada a cipher_build_key64.
; Si %1/%2 son referencias a memoria ([rel var]), se recargan después de la llamada.
%macro CIFRAR_BLOQUE 3
    mov  rdi, %3
    call cipher_build_key64     ; construir key64; retorna valor en rax
    mov  rdx, rax               ; rdx = key64 (antes de que %1/%2 sobreescriban rax)
    mov  rdi, %1                ; buffer a cifrar (recarga de memoria o callee-saved)
    mov  rsi, %2                ; longitud (ídem)
    call cipher_xor             ; cifrar/descifrar in-place con rdx=clave
%endmacro

%endif
