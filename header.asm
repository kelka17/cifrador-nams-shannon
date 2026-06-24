; =============================================================================
; Archivo:     header.asm
; Proyecto:    Cifrador/Descifrador con Análisis de Entropía de Shannon
; Asignatura:  Taller de Programación en Bajo Nivel
; Universidad: UMSS — Facultad de Ciencias y Tecnología
; Descripción: Construcción, validación y checksum de la cabecera binaria CRYP.
; =============================================================================
;
; ==============================================================================
; MÓDULO 1 — CRC-32/ISO-HDLC (IEEE 802.3)
; ==============================================================================
;
;   El CRC-32 (Cyclic Redundancy Check de 32 bits) es un código de detección
;   de errores basado en la división polinomial en GF(2).
;
;   PARÁMETROS CRC-32/ISO-HDLC (estándar Ethernet, ZIP, PNG):
;     Polinomio generador:  G(x) = x³²+x²⁶+x²³+x²²+x¹⁶+x¹²+x¹¹+x¹⁰+x⁸+x⁷+x⁵+x⁴+x²+x+1
;     Representación normal:     0x04C11DB7
;     Representación reflejada:  0xEDB88320  ← usada en la implementación
;     Valor inicial (Init):      0xFFFFFFFF
;     XOR final:                 0xFFFFFFFF
;     Entrada reflejada (LSB-first): sí
;     Salida reflejada: sí
;     Valor de verificación:     header_crc32("123456789", 9) = 0xCBF43926
;
;   PROPIEDADES DE DETECCIÓN DE ERRORES:
;     • Detecta todos los errores de 1 bit.
;     • Detecta todos los errores de 2 bits en mensajes de longitud adecuada.
;     • Detecta todos los errores de longitud ≤ 32 bits (burst errors).
;     • Detecta ≈ 99.9999998% de errores mayores.
;     (Superior a la suma aritmética, que no detecta permutaciones.)
;
;   ALGORITMO BIT A BIT (Galois LFSR, forma reflejada):
;
;     crc = 0xFFFFFFFF
;     para cada byte b en el mensaje:
;       crc = crc XOR b          (XOR en los 8 bits menos significativos)
;       para i en 0..7:
;         si (crc AND 1) == 1:
;           crc = (crc >> 1) XOR 0xEDB88320
;         si no:
;           crc = crc >> 1
;     retornar crc XOR 0xFFFFFFFF
;
;   DEMOSTRACIÓN: header_crc32("", 0) = 0x00000000
;     Init = 0xFFFFFFFF, sin bytes procesados, XOR final: 0xFFFFFFFF XOR 0xFFFFFFFF = 0.  ✓
;
;   INVARIANTE DEL BUCLE EXTERNO (sobre bytes):
;     Antes de procesar el byte en posición i (0 ≤ i ≤ n):
;       eax = CRC parcial de los primeros i bytes del mensaje.
;     Base:  i=0 → eax = 0xFFFFFFFF (init).  ✓
;     Paso:  tras procesar byte i, eax = CRC parcial de los primeros i+1 bytes.
;     Fin:   i=n → eax = CRC(buf[0..n-1]).
;     XOR final: eax = eax XOR 0xFFFFFFFF → CRC-32 completo.  ✓
;
; ==============================================================================
; MÓDULO 2 — CHECKSUM ARITMÉTICO (suma de bytes mod 2³²)
; ==============================================================================
;
;   Definición:
;     checksum(buf, n) = (Σᵢ₌₀^{n−1} buf[i]) mod 2³²
;
;   Propiedades:
;     • O(n): recorre el buffer exactamente una vez.
;     • Detecta errores de byte modificado con probabilidad ≈ 1 − 2⁻³².
;     • No detecta swaps de bytes (limitación de la suma).
;
;   Loop invariant de header_checksum:
;     Antes de la iteración i (0 ≤ i ≤ n):
;       eax = (Σⱼ₌₀^{i−1} buf[j]) mod 2³²
;       rcx = i
;     Base:  i=0 → eax = 0, rcx = 0.  ✓
;     Paso:  eax_nuevo = (eax + buf[i]) mod 2³² = Σⱼ₌₀^{i} buf[j] mod 2³².  ✓
;     Fin:   i=n → eax = Σⱼ₌₀^{n−1} buf[j] mod 2³²  ✓
;
; ==============================================================================
; MÓDULO 2 — CONSTRUCCIÓN DE LA CABECERA (header_build)
; ==============================================================================
;
;   Postcondición formal de header_build(dst, original_len, checksum):
;     Después de la llamada, los 20 bytes en [dst] cumplen:
;       [dst + HEADER.magic_number]  = MAGIC_CRYP   = 0x43525950
;       [dst + HEADER.version]       = HEADER_VERSION = 1
;       [dst + HEADER.original_len]  = original_len  (arg rsi)
;       [dst + HEADER.checksum]      = checksum       (arg edx)
;       [dst + HEADER.reserved]      = 0
;
;   header_build es una función hoja (leaf): no llama a otras funciones, por
;   lo que no requiere prologo/epilogo de marco de pila.
;
; ==============================================================================
; MÓDULO 3 — VALIDACIÓN DE CABECERA (header_validate)
; ==============================================================================
;
;   Especificación:
;     header_validate(src) = 1  sii  [src + HEADER.magic_number] == MAGIC_CRYP
;                           = 0  en otro caso
;
;   Justificación: sólo se verifica el magic number (no el checksum) para una
;   validación rápida de formato. Una validación completa requeriría recalcular
;   el checksum del contenido descifrado, que corresponde al llamador.
;
; ==============================================================================
; MÓDULO 4 — CONVENCIÓN DE LLAMADA (System V AMD64 ABI)
; ==============================================================================
;
;   FUNCIÓN          ARGS (rdi, rsi, rdx)          RETORNO  TIPO
;   ──────────────────────────────────────────────────────────────────────────
;   header_checksum  buf_ptr, length, —             rax      uint32_t
;   header_build     dst_ptr, original_len, cksum   —        void
;   header_validate  src_ptr, —, —                  rax      int (0 o 1)
;
;   header_build es función hoja → sin push/pop, RSP inalterado.
;   header_checksum usa callee-saved rbx, r12 → push/pop obligatorio.
;   header_validate usa sólo rax, eax → sin push/pop.
;
; =============================================================================

%include "include/header.inc"

global header_build
global header_validate
global header_checksum
global header_crc32

; =============================================================================
section .text
; =============================================================================

; =============================================================================
; header_checksum — checksum aritmético de bytes (Σ mod 2³²)
; =============================================================================
; uint32_t header_checksum(const uint8_t *buffer, uint64_t length)
;   rdi = puntero al buffer
;   rsi = longitud en bytes
;   rax = Σ buf[i] mod 2³²  (checksum de 32 bits)
;
; Precondición:  rsi ≥ 0  (rsi = 0 retorna 0 inmediatamente).
; Postcondición: rax = (Σᵢ₌₀^{rsi−1} buf[i]) mod 2³².
;
; Complejidad: O(n) — recorre cada byte exactamente una vez.
;
; Registros:
;   rbx = puntero base al buffer     (callee-saved → push/pop)
;   r12 = longitud                   (callee-saved → push/pop)
;   eax = acumulador checksum 32b    (retorno)
;   rcx = índice i (0..length−1)     (caller-saved)
;   edx = valor del byte actual      (caller-saved)
header_checksum:
    test rsi, rsi               ; ¿buffer vacío?
    jz   .hcs_empty

    push rbx                    ; preservar callee-saved (ABI)
    push r12

    mov  rbx, rdi               ; rbx = buffer base
    mov  r12, rsi               ; r12 = length
    xor  eax, eax               ; eax = acumulador = 0  [Inv(0)]
    xor  rcx, rcx               ; rcx = índice = 0

.hcs_loop:
    cmp  rcx, r12               ; ¿fin del buffer?
    je   .hcs_done

    movzx edx, byte [rbx + rcx] ; edx = buf[i] (zero-extended a 32 bits)
    add  eax, edx               ; acumular (desbordamiento natural → mod 2³²)
                                 ; [Inv(i+1): eax = Σⱼ₌₀^{i} buf[j] mod 2³²]
    inc  rcx
    jmp  .hcs_loop

.hcs_done:
    pop  r12                    ; restaurar callee-saved (ABI, orden inverso)
    pop  rbx
    ret

.hcs_empty:
    xor  eax, eax               ; checksum de buffer vacío = 0
    ret

; =============================================================================
; header_build — construye la estructura HEADER en memoria
; =============================================================================
; void header_build(HEADER *dst, uint64_t original_len, uint32_t checksum)
;   rdi = puntero al buffer de destino (mínimo HEADER_size = 20 bytes)
;   rsi = longitud original del archivo plaintext
;   rdx = checksum calculado sobre el contenido
;
; Postcondición:
;   [rdi + HEADER.magic_number]  = 0x43525950
;   [rdi + HEADER.version]       = 1
;   [rdi + HEADER.original_len]  = rsi
;   [rdi + HEADER.checksum]      = edx
;   [rdi + HEADER.reserved]      = 0
;
; Función hoja: no llama a otras funciones → sin marco de pila.
; Registros: sólo rdi (ptr), rsi (len), rdx/edx (cksum) — todos caller-saved.
header_build:
    ; magic_number (4 bytes): identificador ASCII "CRYP"
    mov  dword [rdi + HEADER.magic_number],  MAGIC_CRYP

    ; version (2 bytes): versión actual del formato
    mov  word  [rdi + HEADER.version],       HEADER_VERSION

    ; original_len (8 bytes): longitud del plaintext antes de cifrar
    mov  qword [rdi + HEADER.original_len],  rsi

    ; checksum (4 bytes): suma de bytes mod 2³² del contenido
    mov  dword [rdi + HEADER.checksum],      edx

    ; reserved (2 bytes): cero — reservado para versiones futuras
    mov  word  [rdi + HEADER.reserved],      0

    ret

; =============================================================================
; header_validate — verifica que el buffer empiece con una cabecera CRYP válida
; =============================================================================
; int header_validate(const HEADER *src)
;   rdi = puntero al buffer (los primeros HEADER_size bytes son la cabecera)
;   rax = 1 si la cabecera es válida (magic == MAGIC_CRYP)
;         0 si la cabecera no es válida
;
; Especificación:
;   header_validate(src) = 1  sii  src[0..3] == 0x43525950
;                         = 0  en cualquier otro caso
;
; Registros: sólo eax, rdi — ambos caller-saved.
header_validate:
    mov  eax, dword [rdi + HEADER.magic_number]  ; leer los 4 bytes del magic
    cmp  eax, MAGIC_CRYP                          ; ¿coincide con "CRYP"?
    jne  .hv_invalid

    mov  eax, 1                 ; cabecera válida → retornar 1
    ret

.hv_invalid:
    xor  eax, eax               ; cabecera inválida → retornar 0
    ret

; =============================================================================
; header_crc32 — CRC-32/ISO-HDLC (IEEE 802.3, Ethernet, ZIP, PNG)
; =============================================================================
; uint32_t header_crc32(const uint8_t *buffer, uint64_t length)
;   rdi = puntero al buffer
;   rsi = longitud en bytes
;   rax = CRC-32 de 32 bits
;
; Parámetros del algoritmo:
;   Polinomio reflejado: 0xEDB88320  (= bit-reversal de 0x04C11DB7)
;   Init:    0xFFFFFFFF
;   XOR final: 0xFFFFFFFF
;   Check:   header_crc32("123456789", 9) = 0xCBF43926
;
; Precondición:  rsi ≥ 0. Si rsi = 0 retorna 0x00000000 (0xFFFFFFFF XOR 0xFFFFFFFF).
;
; Postcondición: rax = CRC-32(buf[0..rsi−1]) según CRC-32/ISO-HDLC.
;
; Complejidad: O(n×8) = O(n). Implementación bit a bit (sin tabla de 1 KB).
;
; Registros:
;   rbx = buffer base              (callee-saved → push/pop)
;   r12 = length                   (callee-saved → push/pop)
;   eax = CRC acumulador           (retorno)
;   rcx = índice de byte           (caller-saved)
;   edx = byte actual (zero-ext)   (caller-saved)
;   r9d = contador de bits (0..7)  (caller-saved)
header_crc32:
    push rbx                    ; preservar callee-saved (ABI)
    push r12

    mov  rbx, rdi               ; rbx = buffer base
    mov  r12, rsi               ; r12 = length

    mov  eax, 0xFFFFFFFF        ; eax = CRC = Init  [Inv(0)]
    xor  rcx, rcx               ; rcx = índice de byte = 0

.crc_byte_loop:
    cmp  rcx, r12               ; ¿procesamos todos los bytes?
    je   .crc_finalize

    movzx edx, byte [rbx + rcx] ; edx = buf[i] (zero-extended)
    xor  al, dl                 ; XOR byte en los 8 LSB del CRC

    ; ── procesar 8 bits (Galois LFSR, LSB-first) ─────────────────────────────
    mov  r9d, 8
.crc_bit_loop:
    test eax, 1                 ; ¿bit menos significativo = 1?
    jz   .crc_no_poly
    shr  eax, 1                 ; desplazar a la derecha 1 bit
    xor  eax, 0xEDB88320        ; XOR con polinomio reflejado
    jmp  .crc_bit_done
.crc_no_poly:
    shr  eax, 1                 ; sólo desplazar (sin XOR)
.crc_bit_done:
    dec  r9d
    jnz  .crc_bit_loop          ; repetir 8 veces

    inc  rcx
    jmp  .crc_byte_loop         ; [Inv(i+1): eax = CRC parcial de buf[0..i]]

.crc_finalize:
    xor  eax, 0xFFFFFFFF        ; XOR final: complemento del CRC acumulado

    pop  r12                    ; restaurar callee-saved (ABI)
    pop  rbx
    ret
