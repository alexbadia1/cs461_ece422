.global _main
.section .text

_main:

push    %ebp
mov     %esp,%ebp

# Your code here (code from lecture)

# Modified to use mov:
#   push $0xb
#   pop %eax
mov $0xb, %eax

# Zero out C and D registers
xor %ecx, %ecx
xor %edx, %edx

# Why not just hard code the \0 instead?
#  push %edx        # \0
push $0x00
push $0x68732f2f
push $0x6e69622f

# Store pointer in ebx
mov %esp, %ebx    # "/bin//sh"

int $0x80

leave
ret
