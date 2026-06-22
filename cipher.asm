; cipher.asm
; Cifrado XOR por bloques de 64 bits.

global cipher_xor

section .text

; void cipher_xor(uint8_t *buffer, uint64_t length, uint64_t key)
; rdi = puntero al buffer
; rsi = longitud en bytes
; rdx = clave de 64 bits
cipher_xor:
    push rbp
    mov rbp, rsp
    
    xor rcx, rcx            ; contador = 0
    
.loop_bloques:
    cmp rcx, rsi            ; ¿contador >= longitud?
    jge .fin
    
    ; Procesar bloque de 8 bytes si es posible
    mov rax, rsi
    sub rax, rcx            ; bytes restantes
    cmp rax, 8
    jl .bytes_restantes     ; si < 8, ir a bytes_restantes
    
    ; Cargar 8 bytes desde buffer[contador]
    mov rax, [rdi + rcx]
    
    ; XOR con la clave
    xor rax, rdx
    
    ; Escribir resultado de vuelta
    mov [rdi + rcx], rax
    
    ; Avanzar 8 bytes
    add rcx, 8
    jmp .loop_bloques
    
.bytes_restantes:
    ; Procesar los últimos < 8 bytes byte a byte
    cmp rcx, rsi
    jge .fin
    
    movzx rax, byte [rdi + rcx]
    xor al, dl              ; XOR con el byte 0 de la clave
    mov [rdi + rcx], al
    
    inc rcx
    jmp .bytes_restantes
    
.fin:
    pop rbp
    ret