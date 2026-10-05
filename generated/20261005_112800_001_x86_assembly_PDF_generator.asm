; x86_64 Assembly: PDF generator
section .data
    msg db 'PDF generator', 0
    len equ $ - msg
section .text
    global _start
_start:
    mov rax, 1      ; sys_write
    mov rdi, 1      ; stdout
    lea rsi, [msg]
    mov rdx, len
    syscall
    mov rax, 60     ; sys_exit
    xor rdi, rdi
    syscall