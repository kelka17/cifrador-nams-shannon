; =============================================================================
; log.asm — Registro de operaciones en cifrador.log (formato CSV)
; Proyecto:    Cifrador/Descifrador con Análisis de Entropía de Shannon
; Asignatura:  Taller de Programación en Bajo Nivel
; Universidad: UMSS — Facultad de Ciencias y Tecnología
; =============================================================================
;
; FUNCIÓN:
;   log_append(mode_str, filename_str, filesize, entropy_before_milli, entropy_after_milli)
;
;   Abre (o crea) cifrador.log en modo append y escribe una línea CSV:
;     modo,archivo,bytes,H_antes_milli,H_despues_milli
;
;   Ejemplo:
;     encrypt,prueba.txt,1024,4521,7893
;     decrypt,prueba.txt.enc,1004,7893,4521
;
;   Si el archivo no puede abrirse, retorna silenciosamente sin error.
;
; CONVENCIÓN: System V AMD64 ABI
;   rdi = mode_str             (null-terminated: "encrypt" o "decrypt")
;   rsi = filename_str         (null-terminated)
;   rdx = filesize             (uint64, bytes)
;   rcx = entropy_before_milli (uint64, H × 1000)
;   r8  = entropy_after_milli  (uint64, H × 1000)
;
; FLAGS DE APERTURA:
;   O_WRONLY = 0x001
;   O_CREAT  = 0x040
;   O_APPEND = 0x400
;   Combinado: 0x441  →  crea si no existe, siempre escribe al final
; =============================================================================

%include "include/syscalls.inc"

global log_append

section .rodata
    log_fname  db "cifrador.log", 0
    log_comma  db ",", 0
    log_nl     db 10, 0

section .bss
    log_fd     resq 1           ; fd abierto durante la escritura
    log_nbuf   resb 22          ; buffer decimal (uint64 max = 20 dígitos)

section .text

; =============================================================================
; log_append — escribe una línea CSV en cifrador.log
; =============================================================================
; TABLA DE REGISTROS (callee-saved):
;   rbx = mode_str
;   r12 = filename_str
;   r13 = filesize
;   r14 = entropy_before_milli
;   r15 = entropy_after_milli
log_append:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov  rbx, rdi               ; guardar argumentos en callee-saved
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    mov  r15, r8

    ; abrir cifrador.log (O_WRONLY|O_CREAT|O_APPEND = 0x441, permisos 0644)
    mov  rax, SYS_OPEN
    lea  rdi, [rel log_fname]
    mov  rsi, 0x441
    mov  rdx, 0644o
    syscall
    test rax, rax
    js   .la_done               ; fallo al abrir → salir silenciosamente
    mov  [rel log_fd], rax

    ; ── escribir: modo,archivo,bytes,H_antes,H_despues\n ─────────────────────
    mov  rdi, rbx
    call .la_wstr               ; modo

    lea  rdi, [rel log_comma]
    call .la_wstr

    mov  rdi, r12
    call .la_wstr               ; nombre de archivo

    lea  rdi, [rel log_comma]
    call .la_wstr

    mov  rdi, r13
    call .la_wuint              ; filesize en bytes

    lea  rdi, [rel log_comma]
    call .la_wstr

    mov  rdi, r14
    call .la_wuint              ; H_antes × 1000

    lea  rdi, [rel log_comma]
    call .la_wstr

    mov  rdi, r15
    call .la_wuint              ; H_despues × 1000

    lea  rdi, [rel log_nl]
    call .la_wstr               ; '\n'

    mov  rax, SYS_CLOSE
    mov  rdi, [rel log_fd]
    syscall

.la_done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ── .la_wstr — escribe cadena null-terminated a log_fd ──────────────────────
; rdi = puntero a cadena null-terminated
; Callee-saved: rbx (guarda el puntero; las syscalls destruyen rdi)
.la_wstr:
    push rbx
    mov  rbx, rdi
    xor  rcx, rcx
.la_ws_len:
    cmp  byte [rbx + rcx], 0
    je   .la_ws_write
    inc  rcx
    jmp  .la_ws_len
.la_ws_write:
    test rcx, rcx
    jz   .la_ws_ret
    mov  rax, SYS_WRITE
    mov  rdi, [rel log_fd]
    mov  rsi, rbx
    mov  rdx, rcx
    syscall
.la_ws_ret:
    pop  rbx
    ret

; ── .la_wuint — convierte uint64 (rdi) a decimal y escribe a log_fd ─────────
; Algoritmo: divide repetidamente por 10, almacena dígitos de atrás hacia
; adelante en log_nbuf, luego escribe el segmento resultante.
; Callee-saved: rbx (puntero en buffer), r12 (valor restante)
.la_wuint:
    push rbx
    push r12

    mov  r12, rdi               ; valor a convertir
    lea  rbx, [rel log_nbuf]
    add  rbx, 21                ; rbx → último byte del buffer
    mov  byte [rbx], 0
    dec  rbx

    test r12, r12
    jnz  .la_wu_loop
    mov  byte [rbx], '0'        ; caso especial: valor == 0
    dec  rbx
    jmp  .la_wu_write

.la_wu_loop:
    test r12, r12
    jz   .la_wu_write
    mov  rax, r12
    xor  rdx, rdx               ; limpiar mitad alta para DIV (requerido)
    mov  rcx, 10
    div  rcx                    ; rax = cociente, rdx = resto (dígito)
    mov  r12, rax
    add  dl, '0'
    mov  [rbx], dl
    dec  rbx
    jmp  .la_wu_loop

.la_wu_write:
    inc  rbx                    ; rbx → primer dígito válido
    lea  rcx, [rel log_nbuf]
    add  rcx, 21
    sub  rcx, rbx               ; rcx = longitud en dígitos

    mov  rax, SYS_WRITE
    mov  rdi, [rel log_fd]
    mov  rsi, rbx
    mov  rdx, rcx
    syscall

    pop  r12
    pop  rbx
    ret
