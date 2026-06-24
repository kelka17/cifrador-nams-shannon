; =============================================================================
; Archivo:     include/header.inc
; Proyecto:    Cifrador/Descifrador con Análisis de Entropía de Shannon
; Asignatura:  Taller de Programación en Bajo Nivel
; Universidad: UMSS — Facultad de Ciencias y Tecnología
; =============================================================================
;
; ==============================================================================
; MÓDULO 1 — MOTIVACIÓN Y DISEÑO DE LA CABECERA
; ==============================================================================
;
;   Propósito: identificar y validar archivos cifrados producidos por este
;   programa, permitiendo un descifrado seguro sin ambigüedad de formato.
;
;   Requisitos de diseño:
;     (a) Identificación: magic number distingue archivos CRYP de cualquier otro.
;     (b) Integridad:     checksum detecta corrupción del contenido cifrado.
;     (c) Tamaño:         original_len permite recuperar el plaintext exacto.
;     (d) Extensibilidad: version y reserved permiten evolucionar el formato.
;     (e) Parseable:      todos los campos son de longitud fija → sin estado.
;
; ==============================================================================
; MÓDULO 2 — DIAGRAMA BINARIO DE LA CABECERA (20 bytes, little-endian)
; ==============================================================================
;
;   Offset  Bytes  Tipo      Campo          Valor            Propósito
;   ──────  ─────  ────────  ─────────────  ───────────────  ─────────────────
;     0       4    uint32_t  magic_number   0x43525950       ASCII "CRYP"
;     4       2    uint16_t  version        0x0001           versión del formato
;     6       8    uint64_t  original_len   tamaño original  bytes del plaintext
;    14       4    uint32_t  checksum       CRC-32           integridad del contenido
;    18       2    uint16_t  reserved       0x0000           alineación / futuro uso
;   ────────────────────────────────────────────────────────────────────────────
;   Total:  20 bytes
;
;   VERIFICACIÓN DEL TAMAÑO:
;     sizeof(magic_number)  = sizeof(uint32_t)  = 4 bytes
;     sizeof(version)       = sizeof(uint16_t)  = 2 bytes
;     sizeof(original_len)  = sizeof(uint64_t)  = 8 bytes
;     sizeof(checksum)      = sizeof(uint32_t)  = 4 bytes
;     sizeof(reserved)      = sizeof(uint16_t)  = 2 bytes
;     Total                 =                    20 bytes  ✓
;
;   NOTA DE ENDIANNESS:
;     x86-64 almacena valores enteros en little-endian.
;     Magic number 0x43525950 en memoria:  50 59 52 43  (bytes 0..3)
;     Leído como ASCII desde offset 0:     'P' 'Y' 'R' 'C'  (orden inverso)
;     Leído como uint32_t con MOV dword:   0x43525950 = 'C' 'R' 'Y' 'P'  ✓
;     (el compilador / MOV reordenan transparentemente el entero)
;
; ==============================================================================
; MÓDULO 3 — CAMPO MAGIC NUMBER
; ==============================================================================
;
;   MAGIC_CRYP = 0x43525950
;     Byte 'C' = 0x43  (ASCII 67)
;     Byte 'R' = 0x52  (ASCII 82)
;     Byte 'Y' = 0x59  (ASCII 89)
;     Byte 'P' = 0x50  (ASCII 80)
;
;   Propósito: cualquier herramienta puede identificar el formato CRYP leyendo
;   los primeros 4 bytes. Si magic != 0x43525950 → archivo no es CRYP → error.
;
;   Analogía: igual al magic de archivos ELF (0x7F454C46 = 0x7F'E''L''F'),
;   PNG (0x89504E47), ZIP (0x504B0304), etc.
;
; ==============================================================================
; MÓDULO 4 — CONVENCIÓN NASM struc / endstruc
; ==============================================================================
;
;   NASM struc define offsets de campos relativos al comienzo de la estructura.
;   Ejemplo de uso con istruc (instanciar en .bss):
;
;     hdr_buf: istruc HEADER
;         at HEADER.magic_number, dd 0
;         at HEADER.version,      dw 0
;         at HEADER.original_len, dq 0
;         at HEADER.checksum,     dd 0
;         at HEADER.reserved,     dw 0
;     iend
;
;   Acceso por offset en código:
;     mov  dword [rdi + HEADER.magic_number], 0x43525950
;     mov  rax,  qword [rsi + HEADER.original_len]
;
;   HEADER_size = 20  (definido automáticamente por endstruc)
;
; =============================================================================

%ifndef HEADER_INC
%define HEADER_INC

; ── constantes de la cabecera CRYP ──────────────────────────────────────────
%define MAGIC_CRYP      0x43525950      ; ASCII "CRYP" como uint32_t little-endian
%define HEADER_VERSION  1               ; versión actual del formato de archivo

; ── estructura HEADER (20 bytes) ─────────────────────────────────────────────
struc HEADER
    .magic_number:  resd 1   ; offset  0, 4 bytes: identificador 0x43525950
    .version:       resw 1   ; offset  4, 2 bytes: versión del formato
    .original_len:  resq 1   ; offset  6, 8 bytes: longitud del plaintext
    .checksum:      resd 1   ; offset 14, 4 bytes: integridad del contenido
    .reserved:      resw 1   ; offset 18, 2 bytes: reservado (= 0)
endstruc                     ; HEADER_size = 20 (definido por NASM)

%endif
