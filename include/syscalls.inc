; include/syscalls.inc
; Numeros de syscall y constantes Linux x86-64.

%ifndef SYSCALLS_INC
%define SYSCALLS_INC

%define SYS_READ    0
%define SYS_WRITE   1
%define SYS_OPEN    2
%define SYS_CLOSE   3
%define SYS_LSEEK   8
%define SYS_MMAP    9
%define SYS_MUNMAP  11
%define SYS_EXIT    60
%define SYS_IOCTL   16

%define TCGETS      0x5401
%define TCSETS      0x5402
%define ECHO_BIT    0x0008
%define LFLAG_OFF   12
%define TERMIOS_SZ  36

%define STDIN       0
%define STDOUT      1
%define STDERR      2

%define O_RDONLY    0
%define O_WRONLY    1
%define O_RDWR      2
%define O_CREAT     64
%define O_TRUNC     512

%define SEEK_SET    0
%define SEEK_CUR    1
%define SEEK_END    2

%define PROT_READ   1
%define PROT_WRITE  2
%define MAP_PRIVATE 2

%endif
