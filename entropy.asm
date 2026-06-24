; =============================================================================
; Archivo:     entropy.asm
; Proyecto:    Cifrador/Descifrador con Análisis de Entropía de Shannon
; Asignatura:  Taller de Programación en Bajo Nivel
; Universidad: UMSS — Facultad de Ciencias y Tecnología
; Descripción: Tabla de frecuencias de 256 bytes y entropía de Shannon vía FPU x87.
; =============================================================================
;
; ==============================================================================
; MÓDULO 1 — DEFINICIÓN FORMAL DE ENTROPÍA DE SHANNON
; ==============================================================================
;
;   Sea X una variable aleatoria discreta con alfabeto Σ = {0, 1, …, 255}.
;   La ENTROPÍA DE SHANNON de orden 1 se define como (Shannon 1948):
;
;     H(X) = −Σᵢ₌₀²⁵⁵ pᵢ · log₂(pᵢ)     [bits / símbolo]
;
;   donde pᵢ = freq[i] / N,   con N = Σᵢ₌₀²⁵⁵ freq[i] (total de bytes).
;
;   PROPIEDADES FUNDAMENTALES:
;
;   (a) Rango:   0 ≤ H(X) ≤ log₂(|Σ|) = log₂(256) = 8 bits/símbolo.
;
;       H = 0   ↔  todo el peso en un único símbolo (distribución degenerada).
;       H = 8   ↔  distribución uniforme (máxima incertidumbre).
;
;   (b) Caso límite pᵢ = 0:  se define  0 · log₂(0) ≜ 0.
;       Justificación analítica:
;         lím_{p→0⁺} p · log₂(p)
;           = lím_{p→0⁺} log₂(p) / (1/p)          (forma ∞/∞)
;           = lím_{p→0⁺} (1/p) / (−1/p²)           (regla de L'Hôpital)
;           = lím_{p→0⁺} (−p) = 0                  ✓
;       Implementación: se omiten las entradas con freq[i] = 0  (jz .ec_next).
;
;   INTERPRETACIÓN CRIPTOGRÁFICA (relevante para el proyecto):
;
;     Texto ASCII plano   →  H ≈ 4–5 bits/byte  (estructura lingüística visible)
;     Archivo binario     →  H ≈ 5–7 bits/byte  (algo de estructura)
;     Cifrado ideal       →  H ≈ 8 bits/byte    (distribución casi uniforme)
;
;   Un cifrador de calidad debe elevar la entropía del archivo al cifrar.
;   Comparar H_antes con H_después es una métrica cuantitativa de la difusión.
;
; ==============================================================================
; MÓDULO 2 — DISEÑO DE LA TABLA DE FRECUENCIAS EN BSS
; ==============================================================================
;
;   ESTRUCTURA EN MEMORIA:
;
;     .bss
;     frequency_table resq 256     ; 256 × 8 = 2048 bytes
;     ┌────────┬────────┬─ … ─┬────────┐
;     │freq[0] │freq[1] │     │freq[255]│  ← 8 bytes (uint64_t) por entrada
;     └────────┴────────┴─ … ─┴────────┘
;       offset:  0       8           2040
;
;   ACCESO:
;     movzx rax, byte [buf + i]   ; rax = valor del byte ∈ [0, 255]
;     inc   qword [table + rax*8] ; frequency_table[rax]++
;
;   TIPO uint64_t:  Evita desbordamiento para archivos de hasta 2⁶⁴ bytes.
;   Alineación:     resq alinea a 8 bytes por defecto → acceso óptimo.
;
; ==============================================================================
; MÓDULO 3 — MECÁNICA DE LA PILA FPU x87 (ciclo a ciclo)
; ==============================================================================
;
;   La pila x87 tiene 8 registros ST(0)–ST(7) (80-bit extended precision).
;   Las instrucciones usadas y su efecto:
;
;   INSTRUCCIÓN          ENTRADA               SALIDA           OPCODE
;   ─────────────────────────────────────────────────────────────────────────
;   FLDZ                 ST0=?                 ST0=0.0          D9 EE
;   FILD m64             ST0=A                 ST0=int(m),ST1=A DB /5
;   FDIVP ST(1),ST(0)    ST0=b, ST1=a          ST0=a/b, pop     DE F9
;   FLD ST(0)            ST0=p                 ST0=p, ST1=p     D9 C0
;   FYL2X                ST0=x, ST1=y          ST0=y·log₂(x)   D9 F1
;   FCHS                 ST0=v                 ST0=−v           D9 E0
;   FADDP ST(1),ST(0)    ST0=b, ST1=a          ST0=a+b, pop     DE C1
;   FISTP m64            ST0=v                 (pop)            DF /7
;   FMULP ST(1),ST(0)    ST0=b, ST1=a          ST0=a·b, pop     DE C9
;
;   NOTA:  `fdiv` sin operandos en NASM → FDIVP ST(1),ST(0)  (opcode DE F9).
;          `faddp` sin operandos        → FADDP ST(1),ST(0)  (opcode DE C1).
;
;   ESTADO DE LA PILA DURANTE UN SÍMBOLO (freq[i] > 0):
;
;     [inicio]  ST0 = H_acc
;     FILD freq   → ST0 = freq[i],   ST1 = H_acc
;     FILD total  → ST0 = total,     ST1 = freq[i],        ST2 = H_acc
;     FDIVP       → ST0 = pᵢ,        ST1 = H_acc
;     FLD ST0     → ST0 = pᵢ,        ST1 = pᵢ,            ST2 = H_acc
;     FYL2X       → ST0 = pᵢ·log₂pᵢ, ST1 = H_acc
;     FCHS        → ST0 = −pᵢ·log₂pᵢ, ST1 = H_acc
;     FADDP       → ST0 = H_acc + (−pᵢ·log₂pᵢ) = H_acc_nuevo
;
; ==============================================================================
; MÓDULO 4 — INVARIANTE DE BUCLE DE entropy_calculate
; ==============================================================================
;
;   Sea i el índice del símbolo actual (0 ≤ i ≤ 256).
;   Definimos la contribución de un símbolo j como:
;     c(j) = −pⱼ · log₂(pⱼ)   si freq[j] > 0  (con pⱼ = freq[j]/total)
;           = 0                 si freq[j] = 0  (por L'Hôpital)
;
;   Invariante de bucle:
;     Inv(i): ST0 = Σⱼ₌₀^{i−1} c(j)
;
;   PRUEBA POR INDUCCIÓN:
;     Base:    i=0  → ST0 = 0.0  (FLDZ inicial).   Inv(0) ✓
;     Paso:    asumiendo Inv(i), tras procesar símbolo i:
;              ST0_nuevo = ST0 + c(i) = Σⱼ₌₀^{i−1} c(j) + c(i)
;                        = Σⱼ₌₀^{i} c(j)            → Inv(i+1) ✓
;     Término: i=256 → ST0 = Σⱼ₌₀²⁵⁵ c(j) = H(X)   ✓
;
; ==============================================================================
; MÓDULO 5 — COMPLEJIDAD Y CONVENCIÓN DE LLAMADA (ABI System V AMD64)
; ==============================================================================
;
;   FUNCIÓN             TIEMPO   ESPACIO  PRECONDICIÓN          RETORNO
;   ─────────────────────────────────────────────────────────────────────────
;   frequency_clear     O(1)     O(1)     —                     —
;   frequency_count     O(n)     O(1)     buf≠NULL, len>0       —  [modifica BSS]
;   entropy_calculate   O(1)     O(1)     frequency_count prev. ST0 = H
;
;   Nota: frequency_clear y entropy_calculate iteran siempre 256 veces
;   (constante fija), independientemente del tamaño del archivo → O(1).
;
;   CONVENCIÓN System V AMD64:
;     Argumentos:   rdi, rsi, rdx, rcx, r8, r9
;     Retorno:      rax (entero) / ST0 (flotante x87)
;     Callee-saved: rbx, rbp, r12–r15  (push/pop obligatorio si se usan)
;     Caller-saved: rax, rcx, rdx, rsi, rdi, r8–r11 (pueden destruirse)
;
;   TABLA DE REGISTROS POR FUNCIÓN:
;
;   frequency_clear:
;     rdi = cursor a frequency_table (caller-saved, no requiere push)
;     rcx = contador descendente (0..255)     (caller-saved)
;
;   frequency_count:
;     rbx = buffer base (callee-saved → push/pop)
;     r12 = length (callee-saved → push/pop)
;     rcx = índice actual i (caller-saved)
;     rax = byte_value = buf[i] (zero-extended)
;     rdx = base de frequency_table (cargada en cada iteración)
;
;   entropy_calculate:
;     rbx = base de frequency_table (callee-saved → push/pop)
;     r12 = total (callee-saved → push/pop; almacenado en [rsp] para FILD)
;     rcx = índice de símbolo i (0..255) (caller-saved)
;     rax = freq[i] (cargado como qword)
;     [rsp]   = total   (operando de memoria para FILD total)
;     [rsp+8] = freq[i] (operando de memoria para FILD freq)
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
;
; Precondición:  ninguna.
; Postcondición: ∀ i ∈ [0,255]: frequency_table[i] = 0.
;
; Invariante de bucle:
;   Antes de la iteración k (0 ≤ k ≤ 256):
;     ∀ j < k: frequency_table[j] = 0
;     rdi = &frequency_table[k]
;     rcx = 256 − k
;
; Complejidad: O(1) — 256 iteraciones fijas.
;
; Registros (todos caller-saved, no requieren push/pop):
;   rdi = cursor al elemento actual (avanza 8 bytes/iter)
;   rcx = contador descendente (256..1)
frequency_clear:
    lea  rdi, [rel frequency_table] ; rdi = &frequency_table[0]
    xor  rax, rax               ; valor de relleno = 0
    mov  rcx, 256               ; 256 qwords = 2048 bytes
    rep  stosq                  ; memset(frequency_table, 0, 2048)
    ret

; =============================================================================
; frequency_count — cuenta las ocurrencias de cada byte en el buffer
; =============================================================================
; void frequency_count(const uint8_t *buffer, uint64_t length)
;   rdi = puntero al inicio del buffer
;   rsi = longitud en bytes
;
; Precondición:  rdi ≠ NULL, rsi > 0 (verificado: retorna si rsi=0).
;                frequency_clear debe haber sido llamado antes si se desea
;                una tabla limpia (o se acepta acumulación sobre tabla existente).
;
; Postcondición: ∀ b ∈ [0,255]:
;                  frequency_table[b] = (valor_previo) + #{i : buffer[i] = b, 0≤i<length}
;
; Invariante de bucle:
;   Antes de la iteración i (0 ≤ i ≤ length):
;     ∀ b: frequency_table[b] ≥ #{j < i : buffer[j] = b}   (conteos acumulados)
;     rcx = i
;
; Complejidad: O(n) — n = length.
;
; Registros:
;   rbx = buffer base                  (callee-saved → push/pop)
;   r12 = length                       (callee-saved → push/pop)
;   rcx = índice i (0..length−1)       (caller-saved)
;   rax = byte_value = buffer[i]       (caller-saved)
;   rdx = base de frequency_table      (caller-saved; recargado por RIP-rel)
frequency_count:
    test rsi, rsi               ; ¿longitud == 0?
    jz   .fct_done              ; sí → nada que contar

    push rbx                    ; preservar callee-saved (ABI)
    push r12

    mov  rbx, rdi               ; rbx = buffer base
    mov  r12, rsi               ; r12 = length
    xor  rcx, rcx               ; rcx = índice (0..length-1)
    lea  rdx, [rel frequency_table] ; rdx = base tabla (constante en el bucle)

.fct_loop:
    cmp  rcx, r12               ; ¿llegamos al final?
    je   .fct_end

    movzx rax, byte [rbx + rcx] ; rax = buffer[rcx] (zero-extended a 64 bits)
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
;   rdi = N = total de bytes (denominador pᵢ = freq[i]/N)
;   Retorna H en ST0 (pila FPU x87).
;
; Precondición:
;   rdi > 0 (verificado: retorna H=0.0 si rdi=0).
;   frequency_count ya fue llamado para rellenar frequency_table.
;
; Postcondición:
;   ST0 = −Σᵢ pᵢ·log₂(pᵢ)   donde pᵢ = frequency_table[i] / rdi,
;         con convención 0·log₂(0) = 0 (entradas con freq=0 se saltan).
;
; Invariante de bucle (véase MÓDULO 4):
;   Inv(i): ST0 = Σⱼ₌₀^{i−1} c(j)   donde c(j)=−pⱼ·log₂pⱼ si freq[j]>0, else 0.
;
; Estado de la pila x87 durante el procesamiento de símbolo i (freq[i]>0):
;   [inicio iter] ST0 = H_acc
;   FILD freq[i]  ST0 = freq,  ST1 = H_acc
;   FILD total    ST0 = total, ST1 = freq,  ST2 = H_acc
;   FDIVP         ST0 = pᵢ,   ST1 = H_acc
;   FLD ST0       ST0 = pᵢ,   ST1 = pᵢ,   ST2 = H_acc
;   FYL2X         ST0 = pᵢ·log₂pᵢ,        ST1 = H_acc
;   FCHS          ST0 = −pᵢ·log₂pᵢ,       ST1 = H_acc
;   FADDP         ST0 = H_acc + (−pᵢ·log₂pᵢ) = H_acc_nuevo
;   [fin iter]    ST0 = H_acc_nuevo
;
; Complejidad: O(1) — 256 iteraciones fijas.
;
; Registros:
;   rbx    = &frequency_table[0]   (callee-saved)
;   r12    = total                  (callee-saved; guardado en [rsp] para FILD)
;   rcx    = índice i (0..255)      (caller-saved)
;   rax    = frequency_table[i]     (caller-saved)
;   [rsp]  = total   (qword en CPU stack para FILD; FILD no acepta registros)
;   [rsp+8]= freq[i] (qword en CPU stack para FILD)
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

    fldz                        ; ST0 = H_acc = 0.0  [Inv(0): suma vacía = 0]

    xor  rcx, rcx               ; rcx = índice de símbolo (0..255)

.ec_loop:
    cmp  rcx, 256               ; ¿procesamos todos los símbolos?
    je   .ec_loop_done

    mov  rax, [rbx + rcx*8]    ; rax = frequency_table[rcx]
    test rax, rax
    jz   .ec_next               ; freq == 0: contribución 0·log₂(0) = 0 (L'Hôpital)

    ; guardar freq en pila para FILD
    mov  [rsp + 8], rax         ; [rsp+8] = freq[i]

    ; ── secuencia FPU para −pᵢ·log₂(pᵢ) ─────────────────────────────────────
    fild qword [rsp + 8]        ; ST0=freq[i],  ST1=H_acc
    fild qword [rsp]            ; ST0=total,    ST1=freq[i], ST2=H_acc
    fdivp st1, st0              ; ST0=freq/total=pᵢ, ST1=H_acc
    fld  st0                    ; duplicar pᵢ: ST0=pᵢ, ST1=pᵢ, ST2=H_acc
    fyl2x                       ; ST0=pᵢ·log₂(pᵢ), ST1=H_acc  [FYL2X: ST0=ST1·log₂(ST0)]
    fchs                        ; ST0=−pᵢ·log₂(pᵢ) (término positivo de entropía)
    faddp                       ; ST0=H_acc+(−pᵢ·log₂(pᵢ)); pop → [Inv(i+1)]

.ec_next:
    inc  rcx
    jmp  .ec_loop

.ec_loop_done:
    add  rsp, 16                ; liberar espacio temporal de pila
    ; ST0 = H  [Inv(256): suma completa = H(X)]

    pop  r12                    ; restaurar callee-saved (ABI, orden inverso)
    pop  rbx
    ret

.ec_zero:
    fldz                        ; H(X) = 0.0 si total == 0 (caso degenerado)
    ret
