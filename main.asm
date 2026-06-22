; main.asm
; Punto de entrada y orquestación del cifrador con ENTROPÍA.

%include "include/syscalls.inc"
%include "include/macros.inc"

global _start
extern sys_open, sys_read, sys_write, sys_close, sys_mmap, sys_munmap, sys_exit
extern cipher_xor
extern frequency_clear, frequency_count, entropy_calculate

section .rodata
    banner db "================================", 10
           db " CIFRADOR NASM", 10
           db "================================", 10, 0
    banner_len equ $ - banner - 1

    usage db "Uso:", 10
          db "  ./cifrador encrypt entrada salida clave", 10
          db "  ./cifrador decrypt entrada salida clave", 10, 0
    usage_len equ $ - usage - 1
    
    error_open db "Error: no se puede abrir archivo", 10, 0
    error_open_len equ $ - error_open - 1
    
    msg_success db "Archivo procesado exitosamente", 10, 0
    msg_success_len equ $ - msg_success - 1
    
    msg_entropy_before db "Calculando entropia antes del cifrado...", 10, 0
    msg_entropy_before_len equ $ - msg_entropy_before - 1
    
    msg_entropy_after db "Calculando entropia despues del cifrado...", 10, 0
    msg_entropy_after_len equ $ - msg_entropy_after - 1

section .bss
    input_buffer resq 1         ; ptr a buffer de entrada
    input_size resq 1           ; tamaño en bytes
    output_fd resq 1            ; file descriptor de salida
    mode_is_encrypt resq 1      ; 1 = encrypt, 0 = decrypt
    entropy_before resq 1       ; H1 (doble en FPU)
    entropy_after resq 1        ; H2 (doble en FPU)

section .text

_start:
    ; Validar argumentos
    mov rax, [rsp]
    cmp rax, 5
    je .ok_args

    ; Imprimir banner
    WRITE STDOUT, banner, banner_len
    
    ; Imprimir uso
    WRITE STDOUT, usage, usage_len
    
    EXIT 1

.ok_args:
    ; Imprimir banner
    WRITE STDOUT, banner, banner_len
    
    ; Extraer argumentos
    ; argv[0] = nombre programa
    ; argv[1] = "encrypt" o "decrypt"
    ; argv[2] = archivo entrada
    ; argv[3] = archivo salida
    ; argv[4] = clave
    
    ; Obtener argv[1] (modo)
    mov rax, [rsp + 8]          ; argv[0]
    mov rax, [rsp + 16]         ; argv[1]
    
    ; Comparar si es "encrypt"
    mov rsi, rax
    mov al, byte [rsi]
    cmp al, 'e'
    je .es_encrypt
    
    xor rax, rax
    jmp .modo_decidido
    
.es_encrypt:
    mov rax, 1
    
.modo_decidido:
    mov [mode_is_encrypt], rax
    
    ; Obtener argv[2] (archivo entrada)
    mov rdi, [rsp + 24]         ; argv[2]
    
    ; Abrir archivo de entrada en lectura
    mov rax, SYS_OPEN
    mov rsi, O_RDONLY
    xor rdx, rdx
    syscall
    
    cmp rax, 0
    jl .error_abriendo
    
    mov r8, rax                 ; r8 = fd entrada
    
    ; Leer archivo completo con mmap
    ; Primero, obtener tamaño con lseek
    mov rdi, r8
    xor rsi, rsi
    mov rdx, SEEK_END
    mov rax, SYS_LSEEK
    syscall
    
    mov [input_size], rax       ; guardar tamaño
    
    ; Volver al inicio
    mov rdi, r8
    xor rsi, rsi
    mov rdx, SEEK_SET
    mov rax, SYS_LSEEK
    syscall
    
    ; Mmap: mapear el archivo en memoria
    xor rdi, rdi                ; addr = NULL (automático)
    mov rsi, [input_size]       ; len = tamaño del archivo
    mov rdx, PROT_READ | PROT_WRITE
    mov r10, MAP_PRIVATE
    mov r8, r8                  ; fd
    xor r9, r9                  ; offset = 0
    mov rax, SYS_MMAP
    syscall
    
    cmp rax, -1
    je .error_abriendo
    
    mov [input_buffer], rax     ; guardar puntero al buffer
    
    ; Cerrar archivo de entrada
    mov rdi, r8
    mov rax, SYS_CLOSE
    syscall
    
    ; ===== CALCULAR ENTROPÍA ANTES DEL CIFRADO =====
    
    WRITE STDOUT, msg_entropy_before, msg_entropy_before_len
    
    ; Limpiar tabla de frecuencias
    call frequency_clear
    
    ; Contar frecuencias en el buffer original
    mov rdi, [input_buffer]
    mov rsi, [input_size]
    call frequency_count
    
    ; Calcular entropía H1
    mov rdi, [input_size]
    call entropy_calculate
    ; Resultado en ST0
    
    ; Guardar H1 en memory (desde ST0 del FPU)
    fstp qword [entropy_before] ; guardar double desde FPU a memoria
    
    ; ===== APLICAR CIFRADO =====
    
    ; Obtener clave (argv[4])
    mov rax, [rsp + 40]         ; argv[4]
    
    ; Convertir string de clave a uint64_t
    ; Por ahora, usamos los primeros 8 bytes como clave
    movzx rdx, byte [rax]
    mov r9, rdx
    movzx rdx, byte [rax + 1]
    shl rdx, 8
    or r9, rdx
    movzx rdx, byte [rax + 2]
    shl rdx, 16
    or r9, rdx
    movzx rdx, byte [rax + 3]
    shl rdx, 24
    or r9, rdx
    movzx rdx, byte [rax + 4]
    shl rdx, 32
    or r9, rdx
    movzx rdx, byte [rax + 5]
    shl rdx, 40
    or r9, rdx
    movzx rdx, byte [rax + 6]
    shl rdx, 48
    or r9, rdx
    movzx rdx, byte [rax + 7]
    shl rdx, 56
    or r9, rdx
    
    ; Llamar cipher_xor(buffer, length, key)
    mov rdi, [input_buffer]
    mov rsi, [input_size]
    mov rdx, r9
    call cipher_xor
    
    ; ===== CALCULAR ENTROPÍA DESPUÉS DEL CIFRADO =====
    
    WRITE STDOUT, msg_entropy_after, msg_entropy_after_len
    
    ; Limpiar tabla de frecuencias
    call frequency_clear
    
    ; Contar frecuencias en el buffer cifrado
    mov rdi, [input_buffer]
    mov rsi, [input_size]
    call frequency_count
    
    ; Calcular entropía H2
    mov rdi, [input_size]
    call entropy_calculate
    ; Resultado en ST0
    
    ; Guardar H2 en memory
    lea rax, [rel entropy_after]
    fstp qword [rax]

    
    ; ===== ESCRIBIR ARCHIVO DE SALIDA =====
    
    ; Obtener argv[3] (archivo salida)
    mov rdi, [rsp + 32]         ; argv[3]
    
    ; Abrir archivo de salida en escritura
    mov rax, SYS_OPEN
    mov rsi, O_WRONLY | O_CREAT | O_TRUNC
    mov rdx, 0o644              ; permisos
    syscall
    
    cmp rax, 0
    jl .error_abriendo
    
    mov r8, rax                 ; r8 = fd salida
    
    ; Escribir buffer cifrado
    mov rdi, r8
    mov rsi, [input_buffer]
    mov rdx, [input_size]
    mov rax, SYS_WRITE
    syscall
    
    ; Cerrar archivo de salida
    mov rdi, r8
    mov rax, SYS_CLOSE
    syscall
    
    ; Munmap
    mov rdi, [input_buffer]
    mov rsi, [input_size]
    mov rax, SYS_MUNMAP
    syscall
    
    ; Éxito
    WRITE STDOUT, msg_success, msg_success_len
    EXIT 0

.error_abriendo:
    WRITE STDERR, error_open, error_open_len
    EXIT 1