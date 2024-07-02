    .text
    .globl strlen
strlen:
    xor %rax, %rax
.L0:
    movb (%rdi), %cl
    test %cl, %cl
    jz .L1
    inc %rax
    inc %rdi
    jmp .L0
.L1:
    ret

