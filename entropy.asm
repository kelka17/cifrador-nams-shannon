; entropy.asm (VERSIÓN SIMPLIFICADA Y CORREGIDA)
; Cálculo de Entropía de Shannon: H = -Σ p·log₂(p)

global entropy_calculate
global frequency_clear
global frequency_count

section .bss
    frequency_table resq 256    ; tabla de 256 QWORD (8 bytes c/u)

section .rodata
    ln2 dq 0.693147180559945    ; ln(2) para convertir ln a log₂

section .text

; void frequency_clear(void)
; Inicializa la tabla de frecuencias a cero
frequency_clear:
    push rbp
    mov rbp, rsp
    
    xor rcx, rcx
    
clear_loop:
    cmp rcx, 256
    jge clear_done
    mov qword [frequency_table + rcx*8], 0
    inc rcx
    jmp clear_loop
    
clear_done:
    pop rbp
    ret

; void frequency_count(uint8_t *buffer, uint64_t length)
; rdi = buffer
; rsi = length
; Cuenta la frecuencia de cada byte en el buffer
frequency_count:
    push rbp
    mov rbp, rsp
    
    xor rcx, rcx                ; contador = 0
    
count_loop:
    cmp rcx, rsi
    jge count_done
    
    movzx rax, byte [rdi + rcx] ; leer byte [0..255]
    inc qword [frequency_table + rax*8] ; incrementar contador
    inc rcx
    jmp count_loop
    
count_done:
    pop rbp
    ret

; double entropy_calculate(uint64_t length)
; rdi = length (longitud total en bytes)
; Retorna en ST0 (FPU stack) = H
; H = -Σ p·log₂(p) donde p = freq[i] / length
entropy_calculate:
    push rbp
    mov rbp, rsp
    sub rsp, 8                  ; espacio para length en stack
    
    ; Guardar length en stack para acceso con fild
    mov qword [rsp], rdi
    
    fldz                        ; ST0 = 0.0 (acumulador H)
    xor rcx, rcx                ; índice de byte (0..255)
    
entropy_loop:
    cmp rcx, 256
    jge entropy_done
    
    mov rax, [frequency_table + rcx*8]  ; freq[i]
    cmp rax, 0
    je entropy_next             ; si freq = 0, saltamos (0·log(0) = 0)
    
    ; Convertir freq a double en FPU
    fild qword [frequency_table + rcx*8]  ; ST0 = freq[i]
    
    ; Cargar length y calcular p = freq[i] / length
    fild qword [rsp]            ; ST0 = length, ST1 = freq[i]
    fdiv                        ; ST0 = freq[i]/length = p
    
    ; Duplicar p para usarlo en log₂(p)
    fdup                        ; ST0 = p, ST1 = p
    
    ; Calcular log₂(p) = ln(p) / ln(2)
    fln                         ; ST0 = ln(p), ST1 = p
    fld qword [rel ln2]         ; ST0 = ln(2), ST1 = ln(p), ST2 = p
    fdiv                        ; ST0 = ln(p)/ln(2) = log₂(p), ST1 = p
    
    ; Calcular p · log₂(p)
    fmul                        ; ST0 = p · log₂(p)
    
    ; Acumular -p·log₂(p)
    fchs                        ; ST0 = -p·log₂(p)
    fadd                        ; ST0 = H + (-p·log₂(p))
    
entropy_next:
    inc rcx
    jmp entropy_loop
    
entropy_done:
    ; ST0 contiene H
    add rsp, 8
    pop rbp
    ret