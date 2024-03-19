from pwn import *

l = listen()
r = remote('::1', l.lport)
_ = l.wait_for_connection()
r.sendline(b'Bye-bye')
print(l.recvline())
r.close()
l.close()
