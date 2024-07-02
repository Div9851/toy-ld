    .text
    .globl print
print:
    mov %rdi, %rbx
    call strlen
    mov %rax, %rdx
    mov %rbx, %rsi
    mov $1, %rdi
    mov $1, %rax
    syscall
    ret
