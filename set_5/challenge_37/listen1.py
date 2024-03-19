from pwn import *

l = listen(1234)
r = remote('localhost', l.lport)
_ = l.wait_for_connection()
l.sendline(b'Hello')
print(r.recvline())
r.close()
l.close()
