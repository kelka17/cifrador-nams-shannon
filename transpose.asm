; transpose.asm (VERSIÓN AUTO-INVERTIBLE)
; Transposición completamente reversible: aplicar dos veces = original
; Usa solo BSWAP que es involution (self-inverse)

global transpose_bytes

section .text

; void transpose_bytes(uint8_t *buffer, uint64_t length)
; rdi = puntero al buffer
; rsi = longitud en bytes
;
; Operación: invertir el orden de bytes en bloques de 8
; BSWAP es auto-invertible: BSWAP(BSWAP(x)) = x
; Por lo tanto: aplicar transpose dos veces = original
transpose_bytes:
    push rbp
    mov rbp, rsp
    
    xor rcx, rcx            ; contador = 0
    
transpose_loop:
    cmp rcx, rsi
    jge transpose_done
    
    ; Calcular bytes restantes
    mov rax, rsi
    sub rax, rcx
    
    ; Si hay 8 o más bytes, procesar bloque de 8
    cmp rax, 8
    jl transpose_residual
    
    ; ===== PROCESAR BLOQUE DE 8 BYTES =====
    
    ; Cargar 8 bytes en RAX
    mov rax, [rdi + rcx]
    
    ; Invertir orden de bytes: BSWAP RAX
    ; Esto intercambia: byte0 ↔ byte7, byte1 ↔ byte6, byte2 ↔ byte5, byte3 ↔ byte4
    ; BSWAP es self-inverse: BSWAP(BSWAP(x)) = x
    bswap rax
    
    ; Escribir resultado
    mov [rdi + rcx], rax
    
    ; Avanzar 8 bytes
    add rcx, 8
    jmp transpose_loop
    
transpose_residual:
    ; Procesar bytes restantes (< 8) byte a byte
    ; Para bytes simples, usamos XOR con máscara (auto-invertible)
    
    cmp rcx, rsi
    jge transpose_done
    
    movzx rax, byte [rdi + rcx]
    
    ; XOR con 0xFF para invertir todos los bits (self-inverse)
    xor al, 0xFF
    
    mov [rdi + rcx], al
    
    inc rcx
    jmp transpose_residual
    
transpose_done:
    pop rbp
    ret