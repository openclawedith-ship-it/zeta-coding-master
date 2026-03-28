; x86_64 Assembly: heap sort algorithm
section .data
    msg db 'heap sort algorithm', 0
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