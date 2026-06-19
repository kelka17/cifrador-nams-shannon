; cipher.asm
; Cifrado XOR por bloques de 64 bits.

global cipher_xor

section .text

; void cipher_xor(uint8_t *buffer, uint64_t length, uint64_t key)
; rdi = puntero al buffer
; rsi = longitud en bytes
; rdx = clave de 64 bits
cipher_xor:
    ret
