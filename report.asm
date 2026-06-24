; =============================================================================
; Archivo:     report.asm
; Proyecto:    Cifrador/Descifrador con Análisis de Entropía de Shannon
; Asignatura:  Taller de Programación en Bajo Nivel
; Universidad: UMSS — Facultad de Ciencias y Tecnología
; Descripción: Generación de reporte HTML con histograma y entropía de Shannon.
; =============================================================================
;
; FUNCIÓN PRINCIPAL:
;   report_generate(fd, filename, filesize, entropy_before_millis, entropy_after_millis)
;
;   Escribe un archivo HTML completo al descriptor fd.  Lee frequency_table
;   (global de entropy.asm) para construir el histograma de 256 barras.
;
;   Estructura del HTML generado:
;     ┌─ Encabezado (DOCTYPE, CSS dark-theme VS Code) ──────────────────────┐
;     │  Tarjeta 1: Información (archivo, tamaño)                           │
;     │  Tarjeta 2: Entropía (barras antes/después, escala 0-8 bits/byte)   │
;     │  Tarjeta 3: Histograma (256 columnas, altura proporcional a freq)   │
;     └─ Footer con créditos ───────────────────────────────────────────────┘
;
; DISEÑO DE HELPERS INTERNOS (no exportados):
;   rpt_write_str(rdi=str*)      — escribe cadena null-terminated a rpt_fd
;   rpt_write_uint(rdi=uint64)   — escribe entero como decimal a rpt_fd
;   rpt_write_millis(rdi=millis) — escribe millis como "X.XXX" a rpt_fd
;
; CONVENCIÓN DE LLAMADA: System V AMD64 ABI
; =============================================================================

%include "include/syscalls.inc"

global report_generate

extern frequency_table
extern sys_write

; =============================================================================
section .rodata
; =============================================================================

; ── Fragmentos HTML estáticos ─────────────────────────────────────────────────
; Divididos en puntos donde se insertan valores dinámicos (nombre, tamaño,
; entropía, anchos de barra).  Las etiquetas HTML usan comillas simples para
; evitar conflictos con las comillas dobles de NASM.

; Fragmento 1: DOCTYPE + <head> + CSS + apertura de tarjeta "Información"
; La cadena termina justo antes del nombre del archivo (valor dinámico).
rpt_p1:
    db "<!DOCTYPE html>", 10
    db "<html lang='es'><head><meta charset='UTF-8'>", 10
    db "<title>Cifrador NASM - Reporte</title>", 10
    db "<style>", 10
    db "*{margin:0;padding:0;box-sizing:border-box}", 10
    db "body{font-family:monospace;background:#1e1e1e;color:#d4d4d4;"
    db      "padding:2em;max-width:860px;margin:0 auto}", 10
    db "h1{color:#569cd6;margin-bottom:.8em}", 10
    db "h2{color:#4ec9b0;margin:1em 0 .5em;font-size:.8em;"
    db    "text-transform:uppercase;letter-spacing:3px}", 10
    db ".card{background:#252526;border:1px solid #3e3e42;"
    db       "border-radius:6px;padding:1.2em;margin:.8em 0}", 10
    db ".row{display:flex;align-items:center;gap:1em;margin:.35em 0}", 10
    db ".lbl{color:#858585;min-width:110px}", 10
    db ".val{color:#ce9178}", 10
    db ".bg{background:#3c3c3c;border-radius:3px;height:14px;flex:1}", 10
    db ".bf{height:100%;border-radius:3px}", 10
    db ".eb{background:#4ec9b0}.ea{background:#f48771}", 10
    db ".hist{display:flex;align-items:flex-end;gap:0;height:150px;"
    db       "background:#1a1a1a;padding:4px 6px 0;border-radius:4px}", 10
    db ".b{background:#569cd6;min-width:2px;flex:1}", 10
    db ".xt{display:flex;justify-content:space-between;"
    db     "color:#858585;font-size:.7em;margin-top:3px}", 10
    db "footer{margin-top:2em;color:#555;font-size:.8em;"
    db        "border-top:1px solid #333;padding-top:1em}", 10
    db "</style></head><body>", 10
    db "<h1>Cifrador NASM &#8212; Reporte de An&#225;lisis</h1>", 10
    db "<div class='card'>", 10
    db "<h2>Informaci&#243;n del archivo</h2>", 10
    db "<div class='row'><span class='lbl'>Archivo:</span>"
    db "<span class='val'>", 0

; Fragmento 2: cierre de nombre → apertura de campo tamaño
rpt_p2:
    db "</span></div>", 10
    db "<div class='row'><span class='lbl'>Tama&#241;o:</span>"
    db "<span class='val'>", 0

; Fragmento 3: cierre de tamaño → tarjeta entropía → antes del valor H_antes
rpt_p3:
    db " bytes</span></div>", 10
    db "</div>", 10
    db "<div class='card'>", 10
    db "<h2>Entrop&#237;a de Shannon (bits/byte)</h2>", 10
    db "<div class='row'><span class='lbl'>Antes:</span>"
    db "<span class='val'>", 0

; Fragmento 4: cierre H_antes → apertura de barra → antes del porcentaje
rpt_p4:
    db " bits/byte</span>"
    db "<div class='bg'><div class='bf eb' style='width:", 0

; Fragmento 5: cierre barra H_antes → apertura fila H_después → antes del valor
rpt_p5:
    db "%'></div></div></div>", 10
    db "<div class='row'><span class='lbl'>Despu&#233;s:</span>"
    db "<span class='val'>", 0

; Fragmento 6: cierre H_después → apertura barra → antes del porcentaje
rpt_p6:
    db " bits/byte</span>"
    db "<div class='bg'><div class='bf ea' style='width:", 0

; Fragmento 7: cierre barra H_después → tarjeta histograma → apertura .hist
rpt_p7:
    db "%'></div></div></div>", 10
    db "</div>", 10
    db "<div class='card'>", 10
    db "<h2>Distribuci&#243;n de bytes (archivo procesado)</h2>", 10
    db "<div class='hist'>", 0

; Prefijo y sufijo de cada barra del histograma
rpt_bar_pre db "<div class='b' style='height:", 0
rpt_bar_suf db "px'></div>", 0

; Fragmento 8: cierre .hist → etiquetas eje X → footer → </html>
rpt_p8:
    db "</div>", 10
    db "<div class='xt'>", 10
    db "<span>0x00</span><span>0x40</span>"
    db "<span>0x80</span><span>0xC0</span><span>0xFF</span>", 10
    db "</div>", 10
    db "</div>", 10
    db "<footer>Generado por Cifrador NASM v1.0 &#8212; UMSS"
    db " &#8212; Facultad de Ciencias y Tecnolog&#237;a</footer>", 10
    db "</body></html>", 10, 0

rpt_str_dot db ".", 0

; =============================================================================
section .bss
; =============================================================================

rpt_fd      resq 1   ; descriptor de archivo de salida (compartido por helpers)
rpt_nbuf    resb 24  ; buffer de scratch para conversión numérica (máx 20 dígitos)

; =============================================================================
section .text
; =============================================================================

; =============================================================================
; rpt_write_str — escribe cadena null-terminated al fd guardado en rpt_fd
; =============================================================================
; rdi = puntero a cadena null-terminated
; Destruye: rax, rcx, rdx, rsi, rdi  (caller-saved — no viola ABI)
; Preserva: rbx, r12-r15             (callee-saved — push/pop rbx)
rpt_write_str:
    push rbx
    mov  rbx, rdi              ; rbx = str (callee-saved: sobrevive la syscall)
    xor  rcx, rcx
.ws_len:
    cmp  byte [rbx + rcx], 0
    je   .ws_do
    inc  rcx
    jmp  .ws_len
.ws_do:
    test rcx, rcx
    jz   .ws_done
    mov  rdi, [rel rpt_fd]     ; fd
    mov  rsi, rbx              ; buf
    mov  rdx, rcx              ; len
    call sys_write
.ws_done:
    pop  rbx
    ret

; =============================================================================
; rpt_write_uint — escribe uint64 como decimal al fd guardado en rpt_fd
; =============================================================================
; rdi = valor a escribir
; Preserva: rbx, r12, r13 (push/pop)
; Algoritmo: división sucesiva por 10, dígitos en orden inverso en rpt_nbuf,
;            luego sys_write desde el puntero al primer dígito.
rpt_write_uint:
    push rbx
    push r12
    push r13
    mov  r12, rdi              ; r12 = valor
    lea  rbx, [rel rpt_nbuf]
    lea  r13, [rbx + 20]       ; r13 = puntero al byte nulo (fin del buffer)
    mov  byte [r13], 0

    test r12, r12
    jnz  .wu_conv
    dec  r13
    mov  byte [r13], '0'
    jmp  .wu_write

.wu_conv:
    test r12, r12
    jz   .wu_write
    mov  rax, r12
    xor  rdx, rdx
    mov  rcx, 10
    div  rcx                   ; rax = cociente, rdx = dígito (0-9)
    mov  r12, rax
    dec  r13
    add  dl, '0'
    mov  [r13], dl
    jmp  .wu_conv

.wu_write:
    ; r13 = inicio de la cadena decimal, rbx+20 = byte nulo
    lea  rax, [rbx + 20]
    sub  rax, r13              ; rax = longitud (número de dígitos)
    mov  rdx, rax
    mov  rsi, r13
    mov  rdi, [rel rpt_fd]
    call sys_write

    pop  r13
    pop  r12
    pop  rbx
    ret

; =============================================================================
; rpt_write_millis — escribe millis como "X.XXX" (ej: 4050 → "4.050")
; =============================================================================
; rdi = millis (0-8000, representación de entropía × 1000)
; Preserva: rbx, r12, r13 (push/pop)
rpt_write_millis:
    push rbx
    push r12
    push r13
    mov  r12, rdi              ; r12 = millis

    ; parte entera = millis / 1000
    mov  rax, r12
    xor  rdx, rdx
    mov  rcx, 1000
    div  rcx                   ; rax = parte entera, rdx = parte decimal (0-999)
    mov  r13, rdx              ; r13 = fracción

    mov  rdi, rax
    call rpt_write_uint        ; escribe parte entera

    lea  rdi, [rel rpt_str_dot]
    call rpt_write_str         ; escribe "."

    ; parte decimal: 3 dígitos con ceros iniciales (ej: 50 → "050")
    lea  rbx, [rel rpt_nbuf]

    mov  rax, r13
    xor  rdx, rdx
    mov  rcx, 100
    div  rcx                   ; rax = centenas, rdx = resto
    add  al, '0'
    mov  [rbx], al

    mov  rax, rdx
    xor  rdx, rdx
    mov  rcx, 10
    div  rcx                   ; rax = decenas, rdx = unidades
    add  al, '0'
    mov  [rbx + 1], al

    add  dl, '0'
    mov  [rbx + 2], dl

    mov  rdi, [rel rpt_fd]
    lea  rsi, [rbx]
    mov  rdx, 3
    call sys_write

    pop  r13
    pop  r12
    pop  rbx
    ret

; =============================================================================
; report_generate — genera el archivo HTML completo
; =============================================================================
; void report_generate(int fd, const char *filename, uint64_t filesize,
;                      uint64_t entropy_before_millis, uint64_t entropy_after_millis)
;
;   rdi = fd del archivo HTML de salida (ya abierto)
;   rsi = puntero al nombre del archivo de entrada (null-terminated)
;   rdx = tamaño del archivo en bytes
;   rcx = entropía antes del cifrado × 1000  (0-8000)
;   r8  = entropía después del cifrado × 1000 (0-8000)
;
; Lee frequency_table (global de entropy.asm) para el histograma.
; La tabla debe estar cargada con la distribución del archivo procesado.
;
; Callee-saved empleados: rbx, r12, r13, r14, r15
report_generate:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov  [rel rpt_fd], rdi     ; guardar fd para todos los helpers
    mov  r12, rsi              ; r12 = filename ptr
    mov  r13, rdx              ; r13 = filesize
    mov  r14, rcx              ; r14 = entropy_before_millis
    mov  r15, r8               ; r15 = entropy_after_millis

    ; ── tarjeta información ───────────────────────────────────────────────────
    lea  rdi, [rel rpt_p1]
    call rpt_write_str

    mov  rdi, r12              ; nombre del archivo
    call rpt_write_str

    lea  rdi, [rel rpt_p2]
    call rpt_write_str

    mov  rdi, r13              ; tamaño en bytes
    call rpt_write_uint

    ; ── tarjeta entropía ──────────────────────────────────────────────────────
    lea  rdi, [rel rpt_p3]
    call rpt_write_str

    mov  rdi, r14              ; H_antes como X.XXX
    call rpt_write_millis

    lea  rdi, [rel rpt_p4]
    call rpt_write_str

    ; ancho barra H_antes: millis / 80  (8000 millis = 100%)
    mov  rax, r14
    xor  rdx, rdx
    mov  rcx, 80
    div  rcx
    cmp  rax, 100
    jbe  .rg_pct1_ok
    mov  rax, 100
.rg_pct1_ok:
    mov  rdi, rax
    call rpt_write_uint

    lea  rdi, [rel rpt_p5]
    call rpt_write_str

    mov  rdi, r15              ; H_después como X.XXX
    call rpt_write_millis

    lea  rdi, [rel rpt_p6]
    call rpt_write_str

    ; ancho barra H_después
    mov  rax, r15
    xor  rdx, rdx
    mov  rcx, 80
    div  rcx
    cmp  rax, 100
    jbe  .rg_pct2_ok
    mov  rax, 100
.rg_pct2_ok:
    mov  rdi, rax
    call rpt_write_uint

    ; ── tarjeta histograma ────────────────────────────────────────────────────
    lea  rdi, [rel rpt_p7]
    call rpt_write_str

    ; encontrar frecuencia máxima (para normalizar alturas)
    ; rbx = frequency_table,  r12 = max_freq
    lea  rbx, [rel frequency_table]
    xor  r12, r12              ; max_freq = 0
    xor  r13, r13              ; índice
.rg_findmax:
    cmp  r13, 256
    je   .rg_bars_start
    mov  rax, [rbx + r13*8]
    cmp  rax, r12
    jle  .rg_fm_next
    mov  r12, rax
.rg_fm_next:
    inc  r13
    jmp  .rg_findmax

.rg_bars_start:
    xor  r13, r13              ; r13 = índice de barra (0..255)

.rg_bar_loop:
    cmp  r13, 256
    je   .rg_bars_done

    lea  rdi, [rel rpt_bar_pre]
    call rpt_write_str         ; "<div class='b' style='height:"
                               ; (rbx, r12, r13 preservados por rpt_write_str)

    ; altura = freq[i] * 150 / max_freq  (min 1 si freq > 0, 0 si freq == 0)
    mov  rax, [rbx + r13*8]    ; rax = freq[i]
    test rax, rax
    jz   .rg_bar_zero

    test r12, r12
    jz   .rg_bar_zero

    imul rax, 150
    xor  rdx, rdx
    div  r12                   ; rax = altura (0-150) — div no modifica r12
    test rax, rax
    jnz  .rg_bar_height
    mov  rax, 1                ; mínimo 1px para frecuencias no nulas
.rg_bar_height:
    mov  rdi, rax
    call rpt_write_uint        ; (r12=max_freq, r13=índice preservados por push/pop)
    jmp  .rg_bar_suffix

.rg_bar_zero:
    mov  rdi, 0
    call rpt_write_uint

.rg_bar_suffix:
    lea  rdi, [rel rpt_bar_suf]
    call rpt_write_str         ; "px'></div>"

    inc  r13
    jmp  .rg_bar_loop

.rg_bars_done:
    ; ── cierre del histograma + footer ────────────────────────────────────────
    lea  rdi, [rel rpt_p8]
    call rpt_write_str

    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
