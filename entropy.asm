; =============================================================================
; Archivo:     entropy.asm
; Proyecto:    Cifrador/Descifrador con Análisis de Entropía de Shannon
; Asignatura:  Taller de Programación en Bajo Nivel
; Universidad: UMSS — Facultad de Ciencias y Tecnología
; Autor(es):   [Nombre Apellido]
; Fecha:       [DD/MM/AAAA]
; Descripción: Tabla de frecuencias y cálculo de entropía de Shannon con FPU x87.
; =============================================================================
;
; FÓRMULA DE ENTROPÍA DE SHANNON:
;   H = −Σᵢ pᵢ · log₂(pᵢ)     donde pᵢ = freq[i] / total
;
; IMPLEMENTACIÓN FPU x87:
;   Para cada símbolo i con freq[i] > 0:
;
;     FILD  freq[i]     → ST0 = freq[i] (entero → real)
;     FILD  total       → ST0 = total,  ST1 = freq[i]
;     FDIV              → FDIVP ST(1),ST(0): ST0 = freq[i]/total = pᵢ
;     FLD   ST0         → duplicar pᵢ: ST0=pᵢ, ST1=pᵢ, ST2=H_acc
;     FYL2X             → ST0 = ST1·log₂(ST0) = pᵢ·log₂(pᵢ), pop ST1
;     FCHS              → ST0 = −pᵢ·log₂(pᵢ)
;     FADDP             → ST0 = H_acc + (−pᵢ·log₂(pᵢ)), pop
;
;   Al final: FSTP qword [dst] guarda H en memoria y vacía la pila x87.
;
; NOTA SOBRE FDIV SIN OPERANDOS:
;   La codificación 0xDE 0xF9 corresponde a FDIVP ST(1),ST(0), que calcula
;   ST(1) / ST(0) y almacena el resultado en ST(1), luego hace pop.
;   Con ST0=total, ST1=freq → resultado: ST0 = freq/total = pᵢ.  ✓
;
; CONVENCIÓN DE LLAMADA: System V AMD64 ABI
;   Argumentos:   rdi (buffer o void), rsi (length o void)
;   Retorno:      ST0 (valor double en pila FPU x87)
; =============================================================================

global entropy_calculate
global frequency_clear
global frequency_count
global frequency_table

; =============================================================================
section .bss
; =============================================================================

frequency_table resq 256        ; tabla: freq_table[byte] = count (256 × 8 bytes)

; =============================================================================
section .text
; =============================================================================

; =============================================================================
; frequency_clear — pone a cero toda la tabla de frecuencias
; =============================================================================
; void frequency_clear(void)
;   Sin argumentos ni valor de retorno.
;   Callee-saved empleados: rcx, rdi (son caller-saved, no necesitan preservarse)
frequency_clear:
    lea  rdi, [rel frequency_table] ; rdi = &frequency_table[0]
    mov  rcx, 256               ; 256 entradas × 8 bytes = 2048 bytes
    xor  rax, rax               ; valor de relleno = 0
.fc_loop:
    mov  qword [rdi], 0         ; limpiar una entrada de 64 bits
    add  rdi, 8                 ; avanzar al siguiente qword
    dec  rcx
    jnz  .fc_loop               ; repetir hasta rcx == 0
    ret

; =============================================================================
; frequency_count — cuenta las ocurrencias de cada byte en el buffer
; =============================================================================
; void frequency_count(const uint8_t *buffer, uint64_t length)
;   rdi = puntero al inicio del buffer
;   rsi = longitud en bytes
;
; Algoritmo: recorrer buffer byte a byte; usar cada byte como índice en
; frequency_table e incrementar el contador correspondiente.
;
; Callee-saved empleados: rbx (puntero base), r12 (longitud)
frequency_count:
    test rsi, rsi               ; ¿longitud == 0?
    jz   .fct_done              ; sí → nada que contar

    push rbx                    ; preservar callee-saved (ABI)
    push r12

    mov  rbx, rdi               ; rbx = buffer base
    mov  r12, rsi               ; r12 = length
    xor  rcx, rcx               ; rcx = índice (0..length-1)

.fct_loop:
    cmp  rcx, r12               ; ¿llegamos al final?
    je   .fct_end

    movzx rax, byte [rbx + rcx] ; rax = buffer[rcx] (zero-extended a 64 bits)
    lea   rdx, [rel frequency_table]
    inc   qword [rdx + rax*8]   ; frequency_table[byte]++

    inc  rcx
    jmp  .fct_loop

.fct_end:
    pop  r12                    ; restaurar callee-saved (ABI)
    pop  rbx

.fct_done:
    ret

; =============================================================================
; entropy_calculate — calcula H = −Σ pᵢ·log₂(pᵢ) con FPU x87
; =============================================================================
; double entropy_calculate(uint64_t total)
;   rdi = total de bytes del buffer (denominator para pᵢ = freq/total)
;   Retorna H en ST0 (pila FPU x87).
;
; Precondición: frequency_count ya fue llamado para llenar frequency_table.
;
; Uso de la pila x87 durante el bucle (símbolo con freq > 0):
;   Antes de entrar al bucle: ST0 = H_acc (acumulador, inicializado con FLDZ)
;   Por cada símbolo:
;     FILD freq[i]  → ST0=freq, ST1=H_acc
;     FILD total    → ST0=total, ST1=freq, ST2=H_acc
;     FDIV          → ST0=p_i, ST1=H_acc        (FDIVP ST(1),ST(0))
;     FLD ST0       → ST0=p_i, ST1=p_i, ST2=H_acc
;     FYL2X         → ST0=p_i·log₂(p_i), ST1=H_acc
;     FCHS          → ST0=−p_i·log₂(p_i), ST1=H_acc
;     FADDP         → ST0=H_acc actualizado
;   Al finalizar: ST0 = H  (retorno en pila FPU)
;
; Callee-saved empleados: rbx (tabla), r12 (total en memoria para FILD)
entropy_calculate:
    test rdi, rdi               ; ¿total == 0?
    jz   .ec_zero               ; sí → entropía 0.0

    push rbx                    ; preservar callee-saved (ABI)
    push r12

    lea  rbx, [rel frequency_table] ; rbx = &frequency_table[0]
    mov  r12, rdi               ; r12 = total (necesario como qword en memoria)

    ; reservar espacio en pila para pasar qwords a FILD
    ; (FILD requiere operando de memoria, no puede leer registros directamente)
    sub  rsp, 16                ; 16 bytes: [rsp] = total, [rsp+8] = freq temp
    mov  [rsp], r12             ; [rsp] = total (para FILD)

    fldz                        ; ST0 = H_acc = 0.0

    xor  rcx, rcx               ; rcx = índice de símbolo (0..255)

.ec_loop:
    cmp  rcx, 256               ; ¿procesamos todos los símbolos?
    je   .ec_loop_done

    mov  rax, [rbx + rcx*8]    ; rax = frequency_table[rcx]
    test rax, rax
    jz   .ec_next               ; freq == 0: contribución 0·log₂(0) se omite (límite: 0)

    ; guardar freq en pila para FILD
    mov  [rsp + 8], rax         ; [rsp+8] = freq[i]

    ; ── secuencia FPU para −pᵢ·log₂(pᵢ) ──────────────────────────────────
    fild qword [rsp + 8]        ; ST0=freq[i],  ST1=H_acc
    fild qword [rsp]            ; ST0=total,    ST1=freq[i], ST2=H_acc
    fdiv                        ; FDIVP ST(1),ST(0): ST0=freq/total=pᵢ, ST1=H_acc
    fld  st0                    ; duplicar pᵢ: ST0=pᵢ, ST1=pᵢ, ST2=H_acc
    fyl2x                       ; ST0=pᵢ·log₂(pᵢ), ST1=H_acc  (FYL2X: ST0=ST1·log₂(ST0))
    fchs                        ; ST0=−pᵢ·log₂(pᵢ) (negar para contribución positiva)
    faddp                       ; ST0=H_acc+(−pᵢ·log₂(pᵢ)); pop → ST0=H_acc

.ec_next:
    inc  rcx
    jmp  .ec_loop

.ec_loop_done:
    add  rsp, 16                ; liberar espacio temporal de pila
    ; ST0 = H (resultado en pila FPU x87, listo para retorno)

    pop  r12                    ; restaurar callee-saved (ABI)
    pop  rbx
    ret

.ec_zero:
    fldz                        ; retornar 0.0 si total == 0
    ret
