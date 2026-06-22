; include/header.inc
; Definicion binaria de la cabecera personalizada CRYP.

%ifndef HEADER_INC
%define HEADER_INC

%define MAGIC_CRYP 0x43525950
%define HEADER_VERSION 1

struc HEADER
    .magic_number: resd 1
    .version:      resw 1
    .original_len: resq 1
    .checksum:     resd 1
    .reserved:     resw 1
endstruc

%define HEADER_size 20          ; 4+2+8+4+2 = 20 bytes

%endif
