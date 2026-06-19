; header.asm
; Construccion, escritura y validacion de cabecera CRYP.

%include "include/header.inc"

global header_build
global header_validate

section .text

; void header_build(HEADER *dst, uint64_t original_len, uint32_t checksum)
header_build:
    ret

; int header_validate(HEADER *src)
header_validate:
    xor eax, eax
    ret
