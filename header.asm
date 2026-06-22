; header.asm
; Construcción, escritura y validación de cabecera CRYP.

%include "include/header.inc"

global header_build
global header_validate
global header_checksum

section .text

; uint32_t header_checksum(uint8_t *buffer, uint64_t length)
; rdi = puntero al buffer
; rsi = longitud en bytes
; Retorna en rax = suma simple de bytes (checksum)
header_checksum:
    push rbp
    mov rbp, rsp
    
    xor rax, rax            ; rax = suma acumulada
    xor rcx, rcx            ; rcx = contador
    
checksum_loop:
    cmp rcx, rsi
    jge checksum_done
    
    movzx r8, byte [rdi + rcx]
    add rax, r8
    inc rcx
    jmp checksum_loop
    
checksum_done:
    pop rbp
    ret

; void header_build(HEADER *dst, uint64_t original_len, uint32_t checksum)
; rdi = puntero a HEADER (destino)
; rsi = longitud original del archivo
; rdx = checksum calculado
header_build:
    push rbp
    mov rbp, rsp
    
    ; Escribir magic number (0x43525950 = 'CRYP')
    mov dword [rdi + HEADER.magic_number], MAGIC_CRYP
    
    ; Escribir versión (1 = XOR puro)
    mov word [rdi + HEADER.version], HEADER_VERSION
    
    ; Escribir longitud original
    mov qword [rdi + HEADER.original_len], rsi
    
    ; Escribir checksum
    mov dword [rdi + HEADER.checksum], edx
    
    ; Escribir reserved como 0
    mov word [rdi + HEADER.reserved], 0
    
    pop rbp
    ret

; int header_validate(HEADER *src)
; rdi = puntero a HEADER (fuente)
; Retorna en rax:
;   0 = válida
;   1 = magic number inválido
;   2 = versión inválida
header_validate:
    push rbp
    mov rbp, rsp
    
    ; Validar magic number
    mov eax, dword [rdi + HEADER.magic_number]
    cmp eax, MAGIC_CRYP
    jne invalid_magic
    
    ; Validar versión (1 o 2)
    mov ax, word [rdi + HEADER.version]
    cmp ax, 1
    je valid_version
    cmp ax, 2
    jne invalid_version
    
valid_version:
    xor eax, eax            ; rax = 0 (válida)
    pop rbp
    ret
    
invalid_magic:
    mov eax, 1              ; rax = 1 (magic inválido)
    pop rbp
    ret
    
invalid_version:
    mov eax, 2              ; rax = 2 (versión inválida)
    pop rbp
    ret