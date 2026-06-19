; entropy.asm
; Calculo de frecuencias, entropia de Shannon con FPU x87 e histograma base.

global entropy_calculate
global frequency_clear
global frequency_count

section .bss
    frequency_table resq 256

section .text

; void frequency_clear(void)
frequency_clear:
    ret

; void frequency_count(uint8_t *buffer, uint64_t length)
frequency_count:
    ret

; double entropy_calculate(uint8_t *buffer, uint64_t length)
; Resultado esperado: ST0 con H.
entropy_calculate:
    fldz
    ret
