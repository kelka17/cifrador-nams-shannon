; =============================================================================
; Archivo:     header.asm
; Proyecto:    Cifrador/Descifrador con Análisis de Entropía de Shannon
; Asignatura:  Taller de Programación en Bajo Nivel
; Universidad: UMSS — Facultad de Ciencias y Tecnología
; Autor(es):   [Nombre Apellido]
; Fecha:       [DD/MM/AAAA]
; Descripción: Construcción y validación de la cabecera binaria CRYP (20 bytes).
; =============================================================================
;
; ESTRUCTURA DE LA CABECERA (20 bytes, little-endian):
;
;   Offset  Tamaño  Campo          Valor
;   ──────  ──────  ─────────────  ──────────────────────────────
;   0       4       magic_number   0x43525950 = ASCII "CRYP"
;   4       2       version        1
;   6       8       original_len   longitud del archivo original
;   14      4       checksum       suma de todos los bytes del contenido
;   18      2       reserved       0x0000
;   Total: 20 bytes
;
; CHECKSUM:
;   Suma aritmética (mod 2³²) de todos los bytes del buffer original.
;   Calculado con un bucle ADD sobre cada byte del buffer.
;
; CONVENCIÓN DE LLAMADA: System V AMD64 ABI
; =============================================================================

%include "include/header.inc"

global header_build
global header_validate
global header_checksum

; =============================================================================
section .text
; =============================================================================

; =============================================================================
; header_checksum — suma de bytes (mod 2³²) como checksum
; =============================================================================
; uint32_t header_checksum(const uint8_t *buffer, uint64_t length)
;   rdi = puntero al buffer
;   rsi = longitud en bytes
;   rax = checksum de 32 bits (suma mod 2³²)
;
; Callee-saved empleados: rbx (buffer base), r12 (length)
header_checksum:
    test rsi, rsi               ; ¿buffer vacío?
    jz   .hcs_empty

    push rbx                    ; preservar callee-saved (ABI)
    push r12

    mov  rbx, rdi               ; rbx = buffer
    mov  r12, rsi               ; r12 = length
    xor  eax, eax               ; eax = acumulador (32 bits, mod 2³²)
    xor  rcx, rcx               ; rcx = índice

.hcs_loop:
    cmp  rcx, r12               ; ¿fin del buffer?
    je   .hcs_done

    movzx rdx, byte [rbx + rcx] ; rdx = buffer[rcx] (zero-extended)
    add  eax, edx               ; acumular (overflow natural → mod 2³²)

    inc  rcx
    jmp  .hcs_loop

.hcs_done:
    pop  r12                    ; restaurar callee-saved (ABI)
    pop  rbx
    ret

.hcs_empty:
    xor  eax, eax               ; checksum de buffer vacío = 0
    ret

; =============================================================================
; header_build — rellena un struct HEADER en memoria
; =============================================================================
; void header_build(HEADER *dst, uint64_t original_len, uint32_t checksum)
;   rdi = puntero al buffer de 20 bytes donde escribir la cabecera
;   rsi = longitud original del archivo (antes de cifrar)
;   rdx = checksum calculado sobre el contenido original
;
; Escribe los 5 campos de HEADER directamente usando offsets definidos en header.inc.
; Sin marco de pila (función hoja, no llama a otras funciones).
header_build:
    ; campo magic_number (4 bytes): 0x43525950 = "CRYP"
    mov  dword [rdi + HEADER.magic_number], MAGIC_CRYP

    ; campo version (2 bytes): 1
    mov  word  [rdi + HEADER.version], HEADER_VERSION

    ; campo original_len (8 bytes): longitud original
    mov  qword [rdi + HEADER.original_len], rsi ; 2.o arg = original_len

    ; campo checksum (4 bytes): checksum del contenido
    mov  dword [rdi + HEADER.checksum], edx     ; 3.er arg = checksum (32 bits)

    ; campo reserved (2 bytes): cero
    mov  word  [rdi + HEADER.reserved], 0

    ret

; =============================================================================
; header_validate — verifica que un buffer comience con cabecera CRYP válida
; =============================================================================
; int header_validate(const HEADER *src)
;   rdi = puntero al buffer cifrado (los primeros 20 bytes son la cabecera)
;   rax = 1 si la cabecera es válida, 0 si no lo es
;
; Validación: comprobar que magic_number == MAGIC_CRYP (0x43525950).
header_validate:
    mov  eax, dword [rdi + HEADER.magic_number] ; leer los 4 bytes del magic
    cmp  eax, MAGIC_CRYP                        ; ¿coincide con "CRYP"?
    jne  .hv_invalid

    mov  eax, 1                 ; cabecera válida → retornar 1
    ret

.hv_invalid:
    xor  eax, eax               ; cabecera inválida → retornar 0
    ret
