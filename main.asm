; =============================================================================
; Archivo:     main.asm
; Proyecto:    Cifrador/Descifrador con Análisis de Entropía de Shannon
; Asignatura:  Taller de Programación en Bajo Nivel
; Universidad: UMSS — Facultad de Ciencias y Tecnología
; Autor(es):   [Nombre Apellido]
; Fecha:       [DD/MM/AAAA]
; Descripción: Punto de entrada. Orquesta CLI, I/O, cifrado y visualización.
; =============================================================================
;
; USO:
;   ./cifrador encrypt <entrada> <salida> <clave>
;   ./cifrador decrypt <entrada> <salida> <clave>
;
; FLUJO ENCRYPT:
;   freq_clear → freq_count → entropy_before →
;   cipher_xor → transpose_encrypt →
;   freq_clear → freq_count → entropy_after →
;   header_build → write(header+buf)
;
; FLUJO DECRYPT:
;   header_validate → transpose_decrypt → cipher_xor → write(buf)
;
; MAPA DE REGISTROS CALLEE-SAVED (después del prólogo):
;   r12 = argv[1] (modo) → decrypt: content_ptr
;   r13 = argv[2] (input) → decrypt: content_len
;   r14 = argv[3] (output, consumido al abrir)
;   r15 = argv[4] (clave, usado en toda la ejecución)
;   rbx = libre / scratch
;
; ESTADO DE LA PILA EN _start (Linux x86-64):
;   [rsp+ 0] = argc
;   [rsp+ 8] = argv[0]
;   [rsp+16] = argv[1]
;   [rsp+24] = argv[2]
;   [rsp+32] = argv[3]
;   [rsp+40] = argv[4]
; =============================================================================

%include "include/syscalls.inc"
%include "include/macros.inc"
%include "include/header.inc"

global _start

extern sys_write, sys_exit
extern io_file_open_read, io_file_open_write, io_file_close
extern io_file_size, io_file_read_all, io_file_write_buf
extern io_free
extern io_print_string

extern cipher_build_key64, cipher_xor
extern transpose_encrypt, transpose_decrypt
extern frequency_clear, frequency_count, entropy_calculate, frequency_table
extern header_build, header_validate, header_checksum
extern display_histogram, display_entropy_panel
extern report_generate

; =============================================================================
section .rodata
; =============================================================================

    banner      db 10, 0x1B, "[1m"
                db "  ================================", 10
                db "   CIFRADOR NASM  v1.0", 10
                db "  ================================", 10
                db 0x1B, "[0m", 0

    usage       db "Uso:", 10
                db "  ./cifrador encrypt <entrada> <salida> <clave>", 10
                db "  ./cifrador decrypt <entrada> <salida> <clave>", 10, 0

    str_encrypt db "encrypt", 0
    str_decrypt db "decrypt", 0

    err_mode     db "Error: modo invalido (use encrypt o decrypt).", 10, 0
    err_open_in  db "Error: no se pudo abrir el archivo de entrada.", 10, 0
    err_open_out db "Error: no se pudo crear el archivo de salida.", 10, 0
    err_mmap     db "Error: fallo mmap del archivo de entrada.", 10, 0
    err_empty    db "Error: el archivo de entrada esta vacio.", 10, 0
    err_write    db "Error: fallo al escribir en el archivo de salida.", 10, 0
    err_magic    db "Error: cabecera CRYP invalida (archivo no cifrado).", 10, 0
    err_small    db "Error: archivo cifrado demasiado pequeno (sin cabecera).", 10, 0

    msg_encrypting db "  Cifrando...", 10, 0
    msg_decrypting db "  Descifrando...", 10, 0
    msg_done       db "  Listo.", 10, 0
    report_fname   db "reporte.html", 0
    msg_report     db "  Reporte HTML: reporte.html", 10, 0

; =============================================================================
section .data
; =============================================================================

    ; Puntero indirecto a frequency_table (símbolo externo en entropy.asm).
    ; El enlazador resuelve 'frequency_table' a su dirección real (R_X86_64_64).
    p_freq_table dq frequency_table

; =============================================================================
section .bss
; =============================================================================

    mode                 resb 1  ; 0=encrypt, 1=decrypt
    fd_in                resq 1  ; descriptor archivo entrada
    fd_out               resq 1  ; descriptor archivo salida
    file_size            resq 1  ; tamaño en bytes del archivo de entrada
    buf_ptr              resq 1  ; puntero al buffer mapeado con mmap
    header_buf           resb 20 ; buffer para la cabecera CRYP (20 bytes exactos)
    display_len          resq 1  ; longitud para el histograma (sin cabecera en decrypt)
    entropy_before_milli resq 1  ; H_antes  × 1000
    entropy_after_milli  resq 1  ; H_después × 1000
    fd_report            resq 1  ; descriptor del archivo HTML de reporte
    input_fname_ptr      resq 1  ; puntero al nombre del archivo de entrada
    exit_code            resb 1  ; 0=éxito, 1=error (BSS default=0)

; =============================================================================
section .text
; =============================================================================

; =============================================================================
; _start — punto de entrada del proceso
; =============================================================================
_start:
    ; ── imprimir banner ───────────────────────────────────────────────────────
    ; NO hay pushes aún: pila en estado puro de _start
    lea  rdi, [rel banner]
    call io_print_string

    ; ── validar argc == 5 ─────────────────────────────────────────────────────
    ; [rsp+0] = argc. No se han hecho pushes, offset directo.
    mov  rax, [rsp]             ; rax = argc (en _start: pila sin frame)
    cmp  rax, 5                 ; ./cifrador modo entrada salida clave = 5 tokens
    je   .args_ok

    lea  rdi, [rel usage]
    call io_print_string
    EXIT 1                      ; sin cleanup: nada que cerrar ni liberar

.args_ok:
    ; ── leer argv[1..4] ANTES de cualquier push ───────────────────────────────
    ; En este punto [rsp+0]=argc, [rsp+8..40]=argv[0..4] (sin pushes previos)
    mov  rcx, [rsp + 16]        ; rcx = argv[1] (modo: "encrypt"/"decrypt")
    mov  rdx, [rsp + 24]        ; rdx = argv[2] (archivo de entrada)
    mov  r8,  [rsp + 32]        ; r8  = argv[3] (archivo de salida)
    mov  r9,  [rsp + 40]        ; r9  = argv[4] (clave ASCII)

    ; ── establecer frame callee-saved (5 pushes) ─────────────────────────────
    push rbx                    ; preservar callee-saved (ABI)
    push r12
    push r13
    push r14
    push r15

    ; mover argv a registros callee-saved (sobreviven todas las llamadas)
    mov  r12, rcx               ; r12 = argv[1] (modo)
    mov  r13, rdx               ; r13 = argv[2] (archivo entrada)
    mov  r14, r8                ; r14 = argv[3] (archivo salida)
    mov  r15, r9                ; r15 = argv[4] (clave)
    mov  [rel input_fname_ptr], rdx  ; guardar ptr al nombre de entrada para el reporte

    ; inicializar fds a -1 (sentinel: BSS 0 es ambiguo con fd stdin)
    mov  qword [rel fd_in],  -1
    mov  qword [rel fd_out], -1

    ; ── parsear modo ──────────────────────────────────────────────────────────
    lea  rdi, [rel str_encrypt]
    mov  rsi, r12               ; comparar argv[1] con "encrypt"
    call str_equal              ; rax = 1 si coincide
    test rax, rax
    jz   .try_decrypt

    mov  byte [rel mode], 0     ; modo = 0 → encrypt
    jmp  .mode_ok

.try_decrypt:
    lea  rdi, [rel str_decrypt]
    mov  rsi, r12               ; comparar argv[1] con "decrypt"
    call str_equal
    test rax, rax
    jz   .err_mode

    mov  byte [rel mode], 1     ; modo = 1 → decrypt

.mode_ok:
    ; ── abrir archivo de entrada ──────────────────────────────────────────────
    mov  rdi, r13               ; r13 = ruta del archivo de entrada
    call io_file_open_read      ; rax = fd o negativo si error
    test rax, rax
    js   .err_open_in
    mov  [rel fd_in], rax       ; guardar fd en variable BSS

    ; ── obtener tamaño ────────────────────────────────────────────────────────
    mov  rdi, rax               ; rdi = fd_in
    call io_file_size           ; rax = tamaño en bytes (o negativo)
    test rax, rax
    js   .err_open_in           ; lseek falló
    jz   .err_empty             ; archivo vacío

    mov  [rel file_size], rax

    ; ── mapear archivo en memoria (mmap PROT_READ|PROT_WRITE, MAP_PRIVATE) ────
    mov  rdi, [rel fd_in]
    mov  rsi, [rel file_size]
    call io_file_read_all       ; rax = dirección del mapeo
    cmp  rax, -4096             ; MAP_FAILED: rax > (uint64)(-4096)
    ja   .err_mmap
    mov  [rel buf_ptr], rax

    ; ── abrir archivo de salida ───────────────────────────────────────────────
    mov  rdi, r14               ; r14 = ruta del archivo de salida
    call io_file_open_write     ; rax = fd o negativo
    test rax, rax
    js   .err_open_out
    mov  [rel fd_out], rax

    ; ── despachar al flujo correspondiente ────────────────────────────────────
    cmp  byte [rel mode], 0
    je   .do_encrypt
    jmp  .do_decrypt

; =============================================================================
; FLUJO DE CIFRADO (encrypt)
; =============================================================================
.do_encrypt:
    lea  rdi, [rel msg_encrypting]
    call io_print_string

    ; ── entropía ANTES del cifrado ────────────────────────────────────────────
    call frequency_clear
    mov  rdi, [rel buf_ptr]
    mov  rsi, [rel file_size]
    call frequency_count        ; frequency_table[byte]++ para cada byte del buffer

    mov  rdi, [rel file_size]   ; rdi = total bytes (para cálculo de pᵢ = freq/total)
    call entropy_calculate      ; retorna H en ST0 (pila FPU x87)
    call fpu_st0_to_milli       ; rax = H × 1000; consume ST0
    mov  [rel entropy_before_milli], rax

    ; ── cifrado XOR + construcción de clave ───────────────────────────────────
    ; CIFRAR_BLOQUE: cipher_build_key64(r15) → rax=key; cipher_xor(buf, len, key)
    CIFRAR_BLOQUE [rel buf_ptr], [rel file_size], r15

    ; ── transposición BSWAP (difusión de bytes) ───────────────────────────────
    mov  rdi, [rel buf_ptr]
    mov  rsi, [rel file_size]
    call transpose_encrypt      ; BSWAP de cada bloque de 8 bytes, in-place

    ; ── entropía DESPUÉS del cifrado ──────────────────────────────────────────
    call frequency_clear
    mov  rdi, [rel buf_ptr]
    mov  rsi, [rel file_size]
    call frequency_count

    mov  rdi, [rel file_size]
    call entropy_calculate      ; ST0 = H_después
    call fpu_st0_to_milli
    mov  [rel entropy_after_milli], rax

    ; para el histograma: mostrar distribución del buffer cifrado (file_size bytes)
    mov  rax, [rel file_size]
    mov  [rel display_len], rax

    ; ── calcular checksum del buffer cifrado ──────────────────────────────────
    mov  rdi, [rel buf_ptr]
    mov  rsi, [rel file_size]
    call header_checksum        ; rax = suma de bytes mod 2³²

    ; ── construir cabecera CRYP (20 bytes) ────────────────────────────────────
    lea  rdi, [rel header_buf]
    mov  rsi, [rel file_size]   ; original_len = file_size (antes de cifrar)
    mov  rdx, rax               ; rdx = checksum (3.er arg)
    call header_build

    ; ── escribir cabecera (20 bytes) en archivo de salida ────────────────────
    mov  rdi, [rel fd_out]
    lea  rsi, [rel header_buf]
    mov  rdx, 20
    call io_file_write_buf      ; loop anti-escritura parcial
    test rax, rax
    js   .err_write

    ; ── escribir buffer cifrado (file_size bytes) ────────────────────────────
    mov  rdi, [rel fd_out]
    mov  rsi, [rel buf_ptr]
    mov  rdx, [rel file_size]
    call io_file_write_buf
    test rax, rax
    js   .err_write

    jmp  .display

; =============================================================================
; FLUJO DE DESCIFRADO (decrypt)
; =============================================================================
.do_decrypt:
    lea  rdi, [rel msg_decrypting]
    call io_print_string

    ; ── verificar tamaño mínimo ANTES de leer la cabecera ───────────────────
    ; (header_validate hace un dword read; necesitamos ≥ 4 bytes para eso)
    mov  rax, [rel file_size]
    cmp  rax, 21                ; < 21 → sin cabecera completa (jb = unsigned)
    jb   .err_small

    ; ── validar cabecera CRYP ────────────────────────────────────────────────
    mov  rdi, [rel buf_ptr]
    call header_validate        ; rax = 1 si magic == 0x43525950 ("CRYP")
    test rax, rax
    jz   .err_magic

    ; ── calcular puntero y longitud del contenido cifrado ────────────────────
    ; Reasignar r12/r13 (los valores argv[1]/argv[2] ya no son necesarios)
    mov  r12, [rel buf_ptr]
    add  r12, 20                ; r12 = content_ptr (saltar los 20 bytes de cabecera)
    mov  r13, [rel file_size]
    sub  r13, 20                ; r13 = content_len (bytes cifrados)

    ; ── transposición inversa (BSWAP es auto-inversa) ─────────────────────────
    mov  rdi, r12               ; rdi = content_ptr
    mov  rsi, r13               ; rsi = content_len
    call transpose_decrypt      ; r12, r13 callee-saved: sobreviven

    ; ── descifrado XOR (auto-inverso con la misma clave) ─────────────────────
    CIFRAR_BLOQUE r12, r13, r15 ; r12/r13 callee-saved: sobreviven cipher_build_key64

    ; ── escribir contenido descifrado (sin la cabecera) ──────────────────────
    mov  rdi, [rel fd_out]
    mov  rsi, r12               ; r12 = content_ptr (callee-saved, aún válido)
    mov  rdx, r13               ; r13 = content_len
    call io_file_write_buf
    test rax, rax
    js   .err_write

    ; ── calcular entropía del resultado descifrado (para visualización) ───────
    call frequency_clear
    mov  rdi, r12               ; r12 = content_ptr (callee-saved)
    mov  rsi, r13               ; r13 = content_len
    call frequency_count        ; r12, r13 preservados (frequency_count los restaura)

    mov  rdi, r13               ; rdi = content_len (total para cálculo de pᵢ)
    call entropy_calculate      ; ST0 = H
    call fpu_st0_to_milli
    mov  [rel entropy_before_milli], rax ; en decrypt: ambos valores iguales
    mov  [rel entropy_after_milli],  rax

    ; para el histograma: mostrar content_len bytes del archivo descifrado
    mov  [rel display_len], r13

    jmp  .display

; =============================================================================
; VISUALIZACIÓN — histograma y panel de entropía
; =============================================================================
.display:
    ; display_histogram(freq_table*, total_bytes)
    ; p_freq_table contiene la dirección de frequency_table (resuelta por el enlazador)
    mov  rdi, [rel p_freq_table]
    mov  rsi, [rel display_len]
    call display_histogram

    mov  rdi, [rel entropy_before_milli]
    mov  rsi, [rel entropy_after_milli]
    call display_entropy_panel  ; panel comparativo antes/después

    lea  rdi, [rel msg_done]
    call io_print_string

    ; ── generar reporte HTML ──────────────────────────────────────────────────
    lea  rdi, [rel report_fname]
    call io_file_open_write    ; rax = fd o negativo si falla
    test rax, rax
    js   .skip_report          ; si no se puede crear, omitir silenciosamente
    mov  [rel fd_report], rax

    mov  rdi, [rel fd_report]
    mov  rsi, [rel input_fname_ptr]
    mov  rdx, [rel display_len]   ; tamaño correcto en ambos modos (sin cabecera en decrypt)
    mov  rcx, [rel entropy_before_milli]
    mov  r8,  [rel entropy_after_milli]
    call report_generate

    mov  rdi, [rel fd_report]
    call io_file_close

    lea  rdi, [rel msg_report]
    call io_print_string

.skip_report:
    jmp  .cleanup

; =============================================================================
; MANEJO DE ERRORES
; =============================================================================
.err_mode:
    lea  rdi, [rel err_mode]
    call io_print_string
    jmp  .exit_err

.err_open_in:
    lea  rdi, [rel err_open_in]
    call io_print_string
    jmp  .exit_err

.err_open_out:
    lea  rdi, [rel err_open_out]
    call io_print_string
    jmp  .exit_err

.err_mmap:
    lea  rdi, [rel err_mmap]
    call io_print_string
    jmp  .exit_err

.err_empty:
    lea  rdi, [rel err_empty]
    call io_print_string
    jmp  .exit_err

.err_write:
    lea  rdi, [rel err_write]
    call io_print_string
    jmp  .exit_err

.err_magic:
    lea  rdi, [rel err_magic]
    call io_print_string
    jmp  .exit_err

.err_small:
    lea  rdi, [rel err_small]
    call io_print_string
    jmp  .exit_err

; =============================================================================
; LIMPIEZA Y SALIDA (único punto de salida — usa exit_code para 0 o 1)
; =============================================================================
.exit_err:
    mov  byte [rel exit_code], 1  ; marcar salida con error

.cleanup:
    ; cerrar fd_in (sentinel -1 significa "no abierto")
    mov  rdi, [rel fd_in]
    cmp  rdi, -1
    je   .skip_close_in
    call io_file_close
.skip_close_in:
    ; cerrar fd_out
    mov  rdi, [rel fd_out]
    cmp  rdi, -1
    je   .skip_close_out
    call io_file_close
.skip_close_out:

    ; liberar mapeo de memoria
    mov  rdi, [rel buf_ptr]
    test rdi, rdi
    jz   .skip_free
    mov  rsi, [rel file_size]
    call io_free
.skip_free:

    pop  r15                    ; restaurar callee-saved (ABI, orden inverso al push)
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    movzx rdi, byte [rel exit_code]  ; código de salida: 0 o 1
    call  sys_exit

; =============================================================================
; HELPERS LOCALES
; =============================================================================

; ─── str_equal — comparación de cadenas null-terminated ─────────────────────
; int str_equal(const char *a, const char *b)
;   rdi = cadena a,  rsi = cadena b
;   rax = 1 si iguales byte a byte hasta '\0', 0 si no
;
; Callee-saved: rbx (a), r12 (b)
str_equal:
    push rbx
    push r12
    mov  rbx, rdi               ; rbx = a (callee-saved: sobrevive cualquier call interno)
    mov  r12, rsi               ; r12 = b
    xor  rcx, rcx               ; rcx = índice de comparación
.se_loop:
    movzx rax, byte [rbx + rcx] ; byte de a
    movzx rdx, byte [r12 + rcx] ; byte de b
    cmp  al, dl
    jne  .se_diff               ; bytes distintos → cadenas diferentes
    test al, al
    jz   .se_equal              ; ambos '\0' simultáneamente → iguales
    inc  rcx
    jmp  .se_loop
.se_equal:
    mov  rax, 1
    pop  r12
    pop  rbx
    ret
.se_diff:
    xor  rax, rax
    pop  r12
    pop  rbx
    ret

; ─── fpu_st0_to_milli — convierte ST0 (double FPU) a uint64 × 1000 ───────────
; Resultado en rax. Consume ST0 de la pila FPU x87.
;
; Algoritmo:
;   push 1000 en CPU stack → FILD lo carga como 1000.0 encima de ST0 (H)
;   FMULP: ST0 = H × 1000; pop
;   FISTP: convertir a int64, guardar en CPU stack, pop FPU
;   pop rax → rax = H × 1000 (truncado a entero)
fpu_st0_to_milli:
    sub  rsp, 8                 ; reservar 8 bytes en CPU stack para operandos FILD/FISTP
    mov  qword [rsp], 1000      ; [rsp] = 1000 (operando entero para FILD)
    fild qword [rsp]            ; ST0=1000.0, ST1=H (FILD empuja en la pila FPU)
    fmulp                       ; FMULP ST(1),ST(0): ST0 = H × 1000; pop → ST0=resultado
    fistp qword [rsp]           ; convertir ST0 a int64, guardar en [rsp], pop FPU
    pop  rax                    ; rax = H × 1000 (truncado hacia cero)
    ret
