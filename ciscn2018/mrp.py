from pwn import *
#from gmpy2 import invert
import hashlib

base= '6543210_edcba987mlkjihgfutsrqponCBAzyxwvKJIHGFEDSRQPONML+ZYXWVUT'

n1 = 0x60339c688f579dd4f661bb3430e18672349f1e8843b062e11abb15d34bdaca8c2c01c18983216af16cb323c17058ed36f233375fe89291585b82e32034ab625896f250e35e9dda1a78d6f3014b4403f4690c1bfae9d984c1a91d9ec2a499ff36e62d2872b677582e1de8ff3f31cdbba408bcddc4f024ad327a5f590f12848d955bb3fef29dbcd49b6918d6880243602cbf9a906df384716a66c9ea144db2d4a5733c7de44db7b2b6a77fd17f34e7e837793114b6f7e7d7b4529523d0eb04300f42f84720dd651e9a653d642dedef29dd388efa64f42a2ae50d7985497f4774c56cdbc2f5a3ea4734e683279328486fe4427d72f2f68465fb5a8a4ac0478b49fb

n2 = 0x6b630677d9178549d6de070923e9d66869a8007b08071fdc4ea3755a97f9f5b03806bb743d570a0e573861cf3636a8c1d76e171bf742a28800b57061047be6a672654df76bd92f488123a7f8e0922ac1d4c62465db3311e4bec159b8827fffe3fb59486a194001fbd68824767cadc26189d2e29b61c8125f5c52dc153f20a86bd086fe13da4853bca02ab60893c2d0a960abce24b96d79afa1289d0cbdc4846dcfc9ea213be13c9e76357cc86714e0220ddaa8462e91dcdac14642cd3648c42b53c7ec0ad396494ed5bd461b2efdb2027a80e582d0c70a5eac18ac4b61a6844c26bb7ba606a9b8991902a002a964fd8b3a9c5ff29a3ab387ab27d8b4acd0fd63

e1 = 0x10001
e2 = 0x10003

def compute_random_str(md5_xor,random_str):
	for i in base:
		for j in base:
			for k in base:
				s = random_str + i + j + k
				h = hashlib.md5(s).hexdigest()
				if h == md5_xor:
					return i + j + k


def func1():
	p.recvuntil("4.Show PQ's TRUE Love\n")
	p.sendline("1")
	p.recvuntil("c:")
	c = p.recvline()[:-1]
	return c

def egcd(a, b):
	if a == 0:
		return (b, 0, 1)
	else:
		g, y, x = egcd(b % a, a)
	return (g, x - (b // a) * y, y)

def modinv(a, m):
	g, x, y = egcd(a, m)
	if g != 1:
		raise Exception('modular inverse does not exist')
	else:
		return x % m

p = process("./task_MrP_Hnhwkzw")
#p = remote("117.78.43.163",31375)
p.recvuntil("Proof your heart: ")
md5 = p.recv(32)
md5_xor = hex(int(md5,16) ^ 0x77777777777777777777777777777777)[2:]
p.recv(1)
random_str = p.recv(13)
last3 = compute_random_str(md5_xor, random_str)
p.sendline(last3)

pc1 = int(func1(),16)
p.sendline("1")
sleep(0.2)
p.sendline("3")
p.recvuntil("c:")
pc2 = int(p.recvline()[:-1],16)
print "pc1 : " + hex(pc1)
print "pc2 : " + hex(pc2)

p.sendline("2")
p.recvuntil("c:")
qc1 = int(p.recvline()[:-1],16)
p.sendline("2")
sleep(0.2)
p.sendline("3")
p.recvuntil("c:")
qc2 = int(p.recvline()[:-1],16)
print "qc1 : " + hex(qc1)
print "qc2 : " + hex(qc2)

s = egcd(e1, e2)
s1 = s[1]
s2 = s[2]

if s1<0:
	s1 = - s1
	pc1 = invert(pc1, n1)
elif s2<0:
	s2 = - s2
	pc2 = invert(pc2, n1)

m1 = pow(pc1,s1,n1)*pow(pc2,s2,n1) % n1

s1 = s[1]
s2 = s[2]

if s1<0:
	s1 = - s1
	qc1 = invert(qc1, n2)
elif s2<0:
	s2 = - s2
	qc2 = invert(qc2, n2)

m2 = pow(qc1,s1,n2)*pow(qc2,s2,n2) % n2

print "m1: " + hex(m1)
print "m2: " + hex(m2)
r1 = p64(m1 & 0xffffffffffffffff)
r1 += p64(m1 >> 64)
r2 = p64(m2 & 0xffffffffffffffff)
r2 += p64(m2 >> 64)
p.sendline('4')
p.sendline(str(hex(m1))[2:])
p.sendline(str(hex(m2))[2:])
p.recv(10)
p.interactive()




