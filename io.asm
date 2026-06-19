; io.asm
; Wrappers de entrada/salida y manejo de archivos usando syscalls directas.

%include "include/syscalls.inc"

global sys_open
global sys_read
global sys_write
global sys_close
global sys_mmap
global sys_munmap
global sys_lseek
global sys_exit

section .text

; int sys_open(const char *path, int flags, mode_t mode)
sys_open:
    mov rax, SYS_OPEN
    syscall
    ret

; ssize_t sys_read(int fd, void *buf, size_t count)
sys_read:
    mov rax, SYS_READ
    syscall
    ret

; ssize_t sys_write(int fd, const void *buf, size_t count)
sys_write:
    mov rax, SYS_WRITE
    syscall
    ret

; int sys_close(int fd)
sys_close:
    mov rax, SYS_CLOSE
    syscall
    ret

; void *sys_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off)
sys_mmap:
    mov rax, SYS_MMAP
    syscall
    ret

; int sys_munmap(void *addr, size_t len)
sys_munmap:
    mov rax, SYS_MUNMAP
    syscall
    ret

; off_t sys_lseek(int fd, off_t offset, int whence)
sys_lseek:
    mov rax, SYS_LSEEK
    syscall
    ret

; noreturn sys_exit(int status)
sys_exit:
    mov rax, SYS_EXIT
    syscall
