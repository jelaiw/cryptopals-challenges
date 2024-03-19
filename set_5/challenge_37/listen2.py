from pwn import *

l = listen()
l.spawn_process('/bin/sh')
r = remote('127.0.0.1', l.lport)
r.sendline(b'echo Goodbye')
print(r.recvline())
r.close()
l.close()
