; =============================================================================
; Archivo:     io.asm
; Proyecto:    Cifrador/Descifrador con Análisis de Entropía de Shannon
; Asignatura:  Taller de Programación en Bajo Nivel
; Universidad: UMSS — Facultad de Ciencias y Tecnología
; Autor(es):   [Nombre Apellido]
; Fecha:       [DD/MM/AAAA]
; Descripción: Wrappers de syscalls Linux x86-64 y utilidades de E/S sin libc.
; =============================================================================
;
; Responsabilidad:
;   • Wrappers de todas las syscalls Linux x86-64 requeridas.
;   • Funciones de impresión en consola: strings, enteros decimales, hex.
;   • Apertura, lectura, escritura y cierre de archivos sin libc.
;   • Alocación/liberación de memoria mediante mmap anónimo.
;
; ─────────────────────────────────────────────────────────────────────────────
; CONVENCIÓN DE LLAMADA: System V AMD64 ABI
; ─────────────────────────────────────────────────────────────────────────────
;
;   Paso de argumentos (función):  rdi, rsi, rdx, rcx, r8, r9
;   Paso de argumentos (syscall):  rdi, rsi, rdx, r10, r8, r9
;   Valor de retorno:              rax
;   Registros callee-saved:        rbx, rbp, r12, r13, r14, r15
;   Registros caller-saved:        rax, rcx, rdx, rsi, rdi, r8, r9, r10, r11
;
;   *** DIFERENCIA CRÍTICA ***
;   La instrucción `syscall` destruye rcx (guarda el RIP de retorno) y r11
;   (guarda RFLAGS). Por eso el kernel espera el 4.° argumento en r10, no rcx.
;   El wrapper sys_mmap mueve rcx → r10 antes de la syscall.
;
; ─────────────────────────────────────────────────────────────────────────────
; TABLA DE FUNCIONES EXPORTADAS
; ─────────────────────────────────────────────────────────────────────────────
;
;   Syscall wrappers:
;     sys_open, sys_read, sys_write, sys_close
;     sys_mmap, sys_munmap, sys_lseek, sys_exit
;
;   Impresión en consola:
;     io_print_string   — cadena null-terminated → stdout
;     io_print_len      — buffer con longitud    → stdout
;     io_print_newline  — '\n'                   → stdout
;     io_print_uint64   — entero sin signo (decimal)
;     io_print_hex64    — entero en hexadecimal con prefijo 0x
;
;   Archivo:
;     io_file_open_read   — abre para lectura
;     io_file_open_write  — crea/trunca para escritura
;     io_file_close       — cierra descriptor
;     io_file_size        — tamaño en bytes vía lseek
;     io_file_read_all    — mapea archivo completo en memoria (mmap)
;     io_file_write_buf   — escribe buffer completo (loop anti escritura parcial)
;
;   Memoria dinámica (sin malloc):
;     io_alloc  — mmap anónimo PROT_READ|PROT_WRITE
;     io_free   — munmap
;
; =============================================================================

%include "include/syscalls.inc"
%include "include/macros.inc"

; ─────────────────────────────────────────────────────────────────────────────
; Exportación de todos los símbolos públicos
; ─────────────────────────────────────────────────────────────────────────────
global sys_open
global sys_read
global sys_write
global sys_close
global sys_mmap
global sys_munmap
global sys_lseek
global sys_exit

global io_print_string
global io_print_len
global io_print_newline
global io_print_uint64
global io_print_hex64

global io_file_open_read
global io_file_open_write
global io_file_close
global io_file_size
global io_file_read_all
global io_file_write_buf

global io_alloc
global io_free

global io_close_and_exit

; =============================================================================
section .data
; =============================================================================

io_newline  db 10               ; carácter LF para io_print_newline
io_hex_pfx  db "0x"            ; prefijo de io_print_hex64 (2 bytes, sin null)

; =============================================================================
section .bss
; =============================================================================

; Buffer compartido para conversiones numéricas.
; Dimensionado para el mayor caso: uint64_t decimal = 20 dígitos.
; También usado por io_print_hex64: "0x" + 16 nibbles = 18 bytes.
; 24 bytes cubre ambos usos sin solapamiento.
io_num_buf  resb 24

; =============================================================================
section .text
; =============================================================================

; =============================================================================
; BLOQUE 1 — WRAPPERS DE SYSCALL
; =============================================================================
; Cada wrapper sólo fija rax con el número de syscall y ejecuta `syscall`.
; Los argumentos llegan ya en los registros correctos (rdi, rsi, rdx…)
; porque el ABI de función y el ABI de syscall coinciden en los tres primeros.
; La excepción es sys_mmap (ver comentario abajo).
; =============================================================================

; ─── sys_open ────────────────────────────────────────────────────────────────
; int sys_open(const char *path, int flags, mode_t mode)
;   rdi = ruta null-terminated
;   rsi = flags de apertura (O_RDONLY, O_WRONLY|O_CREAT|O_TRUNC, …)
;   rdx = modo de creación (p.ej. 0644 octal = 420 decimal)
;   rax = fd asignado por el kernel, o -errno en error
;
; Kernel errno relevantes:
;   -2  ENOENT  archivo no existe
;   -13 EACCES  sin permisos
;   -17 EEXIST  ya existe (con O_EXCL)
sys_open:
    mov rax, SYS_OPEN           ; syscall #2
    syscall
    ret

; ─── sys_read ────────────────────────────────────────────────────────────────
; ssize_t sys_read(int fd, void *buf, size_t count)
;   rdi = descriptor de archivo
;   rsi = buffer destino
;   rdx = bytes a leer (máximo)
;   rax = bytes leídos, 0 = EOF, -errno en error
sys_read:
    mov rax, SYS_READ           ; syscall #0
    syscall
    ret

; ─── sys_write ───────────────────────────────────────────────────────────────
; ssize_t sys_write(int fd, const void *buf, size_t count)
;   rdi = descriptor de archivo (1=stdout, 2=stderr)
;   rsi = buffer fuente
;   rdx = bytes a escribir
;   rax = bytes escritos, o -errno
;
; NOTA: write() puede escribir menos bytes de los pedidos (escritura parcial).
; io_file_write_buf() maneja ese caso con un loop de reintento.
sys_write:
    mov rax, SYS_WRITE          ; syscall #1
    syscall
    ret

; ─── sys_close ───────────────────────────────────────────────────────────────
; int sys_close(int fd)
;   rdi = descriptor a cerrar
;   rax = 0 éxito, -errno en error
sys_close:
    mov rax, SYS_CLOSE          ; syscall #3
    syscall
    ret

; ─── sys_mmap ────────────────────────────────────────────────────────────────
; void *sys_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off)
;
;   Llamada como función (ABI):   rdi, rsi, rdx, rcx, r8, r9
;   Llamada como syscall (kernel): rdi, rsi, rdx, r10, r8, r9
;
;   La diferencia es el 4.° argumento (flags):
;     • ABI de función → rcx
;     • ABI de syscall → r10  (porque `syscall` destruye rcx)
;
;   Este wrapper realiza la conversión rcx → r10 antes de la syscall.
;
;   rax = dirección del mapeo, o -errno (típico: MAP_FAILED si > 0xFFF…F000)
sys_mmap:
    mov r10, rcx                ; flags: ABI función (rcx) → ABI syscall (r10)
    mov rax, SYS_MMAP           ; syscall #9
    syscall
    ret

; ─── sys_munmap ──────────────────────────────────────────────────────────────
; int sys_munmap(void *addr, size_t len)
;   rdi = dirección del mapeo previo
;   rsi = tamaño (debe coincidir con el de mmap)
;   rax = 0 éxito, -errno en error
sys_munmap:
    mov rax, SYS_MUNMAP         ; syscall #11
    syscall
    ret

; ─── sys_lseek ───────────────────────────────────────────────────────────────
; off_t sys_lseek(int fd, off_t offset, int whence)
;   rdi = fd
;   rsi = desplazamiento (con signo, en bytes)
;   rdx = SEEK_SET(0) | SEEK_CUR(1) | SEEK_END(2)
;   rax = nueva posición absoluta, o -errno
sys_lseek:
    mov rax, SYS_LSEEK          ; syscall #8
    syscall
    ret

; ─── sys_exit ────────────────────────────────────────────────────────────────
; [noreturn] void sys_exit(int status)
;   rdi = código de salida (0 = éxito)
;
; El kernel termina el proceso inmediatamente.  Esta función nunca retorna.
sys_exit:
    mov rax, SYS_EXIT           ; syscall #60
    syscall
    ; ── zona muerta: el kernel ya terminó el proceso ──


; =============================================================================
; BLOQUE 2 — IMPRESIÓN EN CONSOLA
; =============================================================================

; ─── io_print_string ─────────────────────────────────────────────────────────
; void io_print_string(const char *str)
;   rdi = puntero a cadena terminada en '\0'
;
; Calcula la longitud con un strlen inline (sin libc) y escribe en stdout.
;
; Registros internos:
;   rbx = copia del puntero base (callee-saved: sobrevive la syscall write)
;   rcx = contador de bytes (se usa antes del write; se destruye en syscall)
io_print_string:
    push rbx
    mov  rbx, rdi               ; guardar puntero en registro callee-saved

    ; ── strlen manual ────────────────────────────────────────────────────────
    xor  rcx, rcx               ; inicializar contador en 0
.ps_count:
    cmp  byte [rbx + rcx], 0    ; ¿byte actual es '\0'?
    je   .ps_write              ; sí → longitud calculada
    inc  rcx                    ; no → avanzar
    jmp  .ps_count

.ps_write:
    test rcx, rcx               ; evitar write(fd, buf, 0) innecesario
    jz   .ps_done

    ; ── sys_write(STDOUT, rbx, rcx) ──────────────────────────────────────────
    mov  rdi, STDOUT
    mov  rsi, rbx               ; buffer = puntero original
    mov  rdx, rcx               ; count  = longitud calculada
    mov  rax, SYS_WRITE
    syscall

.ps_done:
    pop  rbx
    ret

; ─── io_print_len ────────────────────────────────────────────────────────────
; void io_print_len(const char *buf, uint64_t len)
;   rdi = buffer (puede no ser null-terminated)
;   rsi = longitud exacta en bytes
;
; Escribe exactamente 'len' bytes en stdout.  Sin cálculo de longitud.
io_print_len:
    test rsi, rsi
    jz   .pl_done               ; longitud 0 → nada que hacer

    mov  rdx, rsi               ; count = len
    mov  rsi, rdi               ; buf
    mov  rdi, STDOUT
    mov  rax, SYS_WRITE
    syscall

.pl_done:
    ret

; ─── io_print_newline ────────────────────────────────────────────────────────
; void io_print_newline(void)
;
; Escribe un único byte 0x0A (LF) en stdout.
io_print_newline:
    mov  rdi, STDOUT
    lea  rsi, [rel io_newline]  ; dirección RIP-relative del byte '\n'
    mov  rdx, 1
    mov  rax, SYS_WRITE
    syscall
    ret

; ─── io_print_uint64 ─────────────────────────────────────────────────────────
; void io_print_uint64(uint64_t value)
;   rdi = entero sin signo a imprimir en base 10
;
; ALGORITMO DE CONVERSIÓN (división sucesiva):
;   1. Dividir value entre 10 → cociente en rax, dígito en rdx.
;   2. Convertir dígito a ASCII: dígito + '0'.
;   3. Almacenar en io_num_buf desde la posición 22 hacia la 2.
;   4. Repetir hasta value == 0.
;   5. Calcular inicio y longitud; llamar write().
;
; La instrucción DIV opera sobre rdx:rax (128 bits → 64 bits).
; Siempre limpiar rdx antes de dividir (xor rdx, rdx).
;
; Registros internos:
;   rbx = puntero base al buffer (callee-saved)
;   r12 = índice de escritura, viaja de 22 a (primera posición ocupada)
io_print_uint64:
    push rbx
    push r12

    lea  rbx, [rel io_num_buf]
    mov  r12, 22                ; posición de escritura, empieza al final

    mov  rax, rdi               ; cargar value
    test rax, rax
    jnz  .pu_convert

    ; caso especial: valor == 0 → escribir '0' en posición 22
    mov  byte [rbx + 22], '0'
    jmp  .pu_print              ; r12=22 → longitud = 23-22 = 1

.pu_convert:
    mov  rcx, 10                ; divisor constante
.pu_loop:
    test rax, rax
    jz   .pu_done               ; cociente agotado → todos los dígitos escritos
    xor  rdx, rdx               ; limpiar mitad alta antes de DIV
    div  rcx                    ; rax = cociente; rdx = dígito (0-9)
    add  dl, '0'                ; convertir a ASCII
    mov  [rbx + r12], dl        ; guardar dígito
    dec  r12                    ; moverse una posición a la izquierda
    jmp  .pu_loop

.pu_done:
    inc  r12                    ; r12 ahora apunta al primer dígito escrito

.pu_print:
    ; rsi = &io_num_buf[r12]  (primer dígito)
    ; rdx = 23 - r12          (cantidad de dígitos)
    lea  rsi, [rbx + r12]
    mov  rdx, 23
    sub  rdx, r12
    mov  rdi, STDOUT
    mov  rax, SYS_WRITE
    syscall

    pop  r12
    pop  rbx
    ret

; ─── io_print_hex64 ──────────────────────────────────────────────────────────
; void io_print_hex64(uint64_t value)
;   rdi = entero sin signo a imprimir en hexadecimal
;
; Salida: "0x" seguido de exactamente 16 dígitos hex en minúscula.
; Ejemplo: valor 255 → "0x00000000000000ff"
;
; ALGORITMO:
;   - El buffer io_num_buf se usa como: [0]='0' [1]='x' [2..17]=16 nibbles
;   - Se extraen 16 nibbles del LSB al MSB con AND 0xF y SHR 4.
;   - Se almacenan en orden inverso: el LSB va en [rbx+17], el MSB en [rbx+2].
;   - La instrucción LOOP decrementa rcx implícitamente y salta si rcx ≠ 0.
;
; Registros internos:
;   r12 = copia del valor (se va desplazando 4 bits por iteración)
;   rbx = base del buffer io_num_buf
;   rcx = contador para LOOP (16 iteraciones)
io_print_hex64:
    push rbx
    push r12

    mov  r12, rdi               ; guardar valor (se va shifteando)
    lea  rbx, [rel io_num_buf]

    ; escribir prefijo "0x" en posiciones 0 y 1
    mov  byte [rbx],     '0'
    mov  byte [rbx + 1], 'x'

    ; ── bucle de 16 iteraciones (un nibble por iteración) ────────────────────
    ; rcx=16 → posición [rbx+17] (LSB)
    ; rcx=1  → posición [rbx+2]  (MSB)
    ; fórmula de índice: rbx + rcx + 1
    mov  rcx, 16

.ph_loop:
    mov  rax, r12
    and  rax, 0x0F              ; extraer nibble menos significativo actual
    cmp  al, 9
    jle  .ph_digit              ; 0-9 → sumar '0'
    add  al, 'a' - 10           ; a-f → sumar offset para letra minúscula
    jmp  .ph_store
.ph_digit:
    add  al, '0'
.ph_store:
    mov  [rbx + rcx + 1], al   ; almacenar en posición correcta
    shr  r12, 4                 ; siguiente nibble
    loop .ph_loop               ; dec rcx; jmp si rcx ≠ 0

    ; escribir "0x" + 16 nibbles = 18 bytes totales
    mov  rdi, STDOUT
    mov  rsi, rbx
    mov  rdx, 18
    mov  rax, SYS_WRITE
    syscall

    pop  r12
    pop  rbx
    ret


; =============================================================================
; BLOQUE 3 — MANEJO DE ARCHIVOS
; =============================================================================

; ─── io_file_open_read ───────────────────────────────────────────────────────
; int io_file_open_read(const char *path)
;   rdi = ruta null-terminated
;   rax = fd (negativo si no existe o sin permisos de lectura)
;
; O_RDONLY = 0: el archivo debe existir previamente.
io_file_open_read:
    mov  rsi, O_RDONLY          ; flags: solo lectura
    xor  rdx, rdx               ; mode: ignorado con O_RDONLY
    mov  rax, SYS_OPEN
    syscall
    ret

; ─── io_file_open_write ──────────────────────────────────────────────────────
; int io_file_open_write(const char *path)
;   rdi = ruta null-terminated
;   rax = fd (negativo en error)
;
; Flags combinados:
;   O_WRONLY (1)  — solo escritura
;   O_CREAT  (64) — crear si no existe
;   O_TRUNC  (512)— truncar a 0 si existe
; Mode 420 = octal 0644 = rw-r--r-- (se aplica solo al crear el archivo)
io_file_open_write:
    mov  rsi, O_WRONLY | O_CREAT | O_TRUNC
    mov  rdx, 420               ; 0o644: rw-r--r--
    mov  rax, SYS_OPEN
    syscall
    ret

; ─── io_file_close ───────────────────────────────────────────────────────────
; int io_file_close(int fd)
;   rdi = descriptor a cerrar
;   rax = 0 éxito, -errno en error
;
; Cerrar es obligatorio para vaciar buffers del kernel y liberar el fd.
io_file_close:
    mov  rax, SYS_CLOSE
    syscall
    ret

; ─── io_file_size ────────────────────────────────────────────────────────────
; int64_t io_file_size(int fd)
;   rdi = fd abierto
;   rax = tamaño en bytes, o valor negativo si error
;
; ALGORITMO:
;   1. lseek(fd, 0, SEEK_END) → rax = número de bytes (posición final).
;   2. Guardar rax en pila.
;   3. lseek(fd, 0, SEEK_SET) → rebobinar al inicio (para lectura posterior).
;   4. Recuperar tamaño de pila y retornar.
;
; Si el primer lseek falla (rax < 0) se salta directamente al retorno
; sin hacer el segundo lseek ni el push/pop extra.
;
; Registro r12: fd preservado entre las dos llamadas lseek.
io_file_size:
    push r12
    mov  r12, rdi               ; guardar fd en callee-saved

    ; paso 1: ir al final → rax = tamaño
    xor  rsi, rsi               ; offset = 0
    mov  rdx, SEEK_END
    mov  rax, SYS_LSEEK
    syscall
    test rax, rax
    js   .fs_error              ; si rax < 0: error, no hacer rewind

    push rax                    ; guardar tamaño en pila

    ; paso 2: rebobinar al inicio
    mov  rdi, r12               ; fd restaurado
    xor  rsi, rsi               ; offset = 0
    mov  rdx, SEEK_SET
    mov  rax, SYS_LSEEK
    syscall
    ; ignoramos el resultado del rewind (posición 0 en caso normal)

    pop  rax                    ; recuperar tamaño guardado

.fs_error:
    ; si hubo error en paso 1, rax es el código negativo de errno
    pop  r12
    ret

; ─── io_file_read_all ────────────────────────────────────────────────────────
; void *io_file_read_all(int fd, uint64_t size)
;   rdi = fd del archivo abierto para lectura
;   rsi = tamaño en bytes (obtenido con io_file_size)
;   rax = dirección del mapeo en memoria virtual
;
; Mapea el archivo completo en el espacio de direcciones del proceso.
; Mucho más eficiente que leer en chunks para archivos grandes.
; El resultado es un puntero a los bytes del archivo; el contenido es
; idéntico al que leeríamos con read().
;
; Para liberar: io_free(ptr, size).
;
; syscall mmap(2):
;   addr   = NULL                      → el kernel elige la dirección
;   len    = size                      → tamaño total
;   prot   = PROT_READ|PROT_WRITE (3) → lectura/escritura (cifrado in-place)
;   flags  = MAP_PRIVATE(2)            → copia privada; escrituras no afectan el archivo en disco
;   fd     = fd
;   offset = 0            → desde el inicio del archivo
;
; NOTA: Los flags van en r10 para la syscall (no en rcx).
;       Se carga r10 directamente aquí para evitar llamar a sys_mmap
;       y tener que mover rcx→r10 en el wrapper.
io_file_read_all:
    push r12
    push r13
    mov  r12, rdi               ; guardar fd
    mov  r13, rsi               ; guardar size

    xor  rdi, rdi               ; addr   = NULL
    mov  rsi, r13               ; len    = size
    mov  rdx, PROT_READ | PROT_WRITE ; prot = lectura/escritura (cifrado in-place)
    mov  r10, MAP_PRIVATE            ; flags = copia privada; escrituras no tocan el archivo (r10 para syscall)
    mov  r8,  r12               ; fd
    xor  r9,  r9                ; offset = 0
    mov  rax, SYS_MMAP
    syscall

    pop  r13
    pop  r12
    ret

; ─── io_alloc ────────────────────────────────────────────────────────────────
; void *io_alloc(uint64_t size)
;   rdi = bytes a reservar
;   rax = puntero al bloque (o MAP_FAILED si error)
;
; Equivalente de malloc() pero usando mmap anónimo directamente.
; Sin libc, esta es la única forma portable de obtener memoria dinámica.
;
; MAP_ANONYMOUS (0x20) | MAP_PRIVATE (0x02) = 0x22
; PROT_READ (1) | PROT_WRITE (2) = 3
; fd = -1 porque no hay archivo de respaldo (anónimo).
io_alloc:
    mov  rsi, rdi               ; len    = size (salvar antes de destruir rdi)
    xor  rdi, rdi               ; addr   = NULL
    mov  rdx, 3                 ; prot   = PROT_READ | PROT_WRITE
    mov  r10, 0x22              ; flags  = MAP_PRIVATE | MAP_ANONYMOUS
    mov  r8,  -1                ; fd     = -1 (anónimo)
    xor  r9,  r9                ; offset = 0
    mov  rax, SYS_MMAP
    syscall
    ret

; ─── io_free ─────────────────────────────────────────────────────────────────
; int io_free(void *addr, uint64_t size)
;   rdi = dirección obtenida de io_alloc o io_file_read_all
;   rsi = tamaño (el mismo que se pasó al reservar)
;   rax = 0 éxito, -errno en error
;
; La dirección y el tamaño deben coincidir exactamente con los del mmap.
io_free:
    mov  rax, SYS_MUNMAP
    syscall
    ret

; ─── io_close_and_exit ───────────────────────────────────────────────────────
; [noreturn] void io_close_and_exit(int fd, int code)
;   rdi = descriptor a cerrar
;   rsi = código de salida deseado (0 = éxito, ≠0 = error de la aplicación)
;
; Comportamiento:
;   1. Llama sys_close(fd).
;   2. Si sys_close tiene éxito (rax == 0), sale con el código recibido en rsi.
;   3. Si sys_close falla  (rax <  0), sale con -rax (errno positivo) para
;      que el shell pueda detectar la causa del fallo: "exit $?"
;
; Convención de códigos usada en el proyecto:
;   0          — éxito
;   1..127     — errores de la aplicación (definidos por el caller)
;   errno > 0  — error del kernel en sys_close (EBADF=9, EIO=5, etc.)
;
; Esta función nunca retorna al caller.
io_close_and_exit:
    push rsi                        ; preservar código de salida deseado

    ; sys_close(fd) — rdi ya contiene el fd
    mov  rax, SYS_CLOSE
    syscall                         ; rax = 0 éxito | -errno en error

    pop  rdi                        ; rdi = código de salida deseado

    test rax, rax
    jns  .cae_exit                  ; rax >= 0: close OK → usar código original

    neg  rax                        ; rax = errno positivo (p.ej. EBADF=9)
    mov  rdi, rax                   ; código de salida = errno del fallo

.cae_exit:
    mov  rax, SYS_EXIT
    syscall
    ; zona muerta: el kernel terminó el proceso

; ─── io_file_write_buf ───────────────────────────────────────────────────────
; ssize_t io_file_write_buf(int fd, const void *buf, uint64_t len)
;   rdi = fd destino
;   rsi = buffer fuente
;   rdx = total de bytes a escribir
;   rax = bytes escritos total, o negativo en error
;
; ¿POR QUÉ EL LOOP?
;   write(2) puede retornar menos bytes que los solicitados (escritura parcial).
;   Esto ocurre al escribir en pipes llenos, sockets, o discos llenos parcialmente.
;   El loop garantiza que se escriba el buffer completo o se detecte un error.
;
; Registros callee-saved empleados (se preservan a través de syscalls):
;   rbx = fd
;   r12 = puntero base al buffer
;   r13 = total de bytes a escribir
;   r14 = bytes escritos acumulados (progreso)
io_file_write_buf:
    push rbx
    push r12
    push r13
    push r14

    mov  rbx, rdi               ; fd
    mov  r12, rsi               ; puntero base al buffer
    mov  r13, rdx               ; total a escribir
    xor  r14, r14               ; bytes escritos = 0

.wbuf_loop:
    cmp  r14, r13
    jge  .wbuf_done             ; ya escribimos todo → salir

    mov  rdi, rbx               ; fd
    lea  rsi, [r12 + r14]       ; buffer + offset acumulado
    mov  rdx, r13
    sub  rdx, r14               ; bytes restantes = total - escritos
    mov  rax, SYS_WRITE
    syscall

    test rax, rax
    js   .wbuf_error            ; rax < 0 → error del kernel
    jz   .wbuf_error            ; rax = 0 → imposible avanzar (dispositivo lleno)

    add  r14, rax               ; acumular bytes escritos en esta iteración
    jmp  .wbuf_loop

.wbuf_done:
    mov  rax, r14               ; retornar total escrito
    jmp  .wbuf_ret

.wbuf_error:
    ; rax contiene el código de error negativo (-errno) de la última syscall

.wbuf_ret:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
