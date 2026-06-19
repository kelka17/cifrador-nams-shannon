# Cifrador / Descifrador de Archivos con Analisis de Entropia de Shannon

Proyecto universitario implementado enteramente en NASM x86-64 para Linux, usando solo syscalls directas del kernel.

## Estructura

```text
.
├── main.asm
├── io.asm
├── cipher.asm
├── transpose.asm
├── entropy.asm
├── header.asm
├── display.asm
├── include/
│   ├── syscalls.inc
│   ├── macros.inc
│   └── header.inc
├── Makefile
└── README.md
```

## Modulos

- `main.asm`: punto de entrada y coordinacion general.
- `io.asm`: wrappers NASM para syscalls Linux.
- `cipher.asm`: cifrado XOR por bloques de 64 bits.
- `transpose.asm`: transposicion reversible de bytes.
- `entropy.asm`: frecuencias y entropia de Shannon con FPU x87.
- `header.asm`: cabecera binaria `CRYP`.
- `display.asm`: mensajes, colores ANSI e histogramas ASCII.

## Compilacion

```bash
make
```

## Ejecucion esperada

```bash
./cifrador encrypt entrada.txt salida.enc clave
./cifrador decrypt salida.enc recuperado.txt clave
```

Esta primera version establece la estructura base del proyecto. Los modulos se completaran progresivamente.
