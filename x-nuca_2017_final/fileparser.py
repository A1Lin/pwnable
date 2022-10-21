from pwn import *
context.log_level = "debug"
p = process("./fileparser")

with open("id^%000000,sig^%11,src^%000060,op^%int32,pos^%476,val^%-1","rb") as f:
    data = f.read()

p.send(data)
p.recv()
p.interactive()