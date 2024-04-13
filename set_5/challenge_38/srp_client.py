from pwn import *
import json
from getpass import getpass
from secrets import randbelow
from Crypto.Util.number import long_to_bytes
import hmac
from srp_helper import client_x

# A large safe prime (N = 2q+1, where q is prime)
# All arithmetic is done modulo N
# (generated using "openssl dhparam -text 1024")
N = """00:c0:37:c3:75:88:b4:32:98:87:e6:1c:2d:a3:32:
       4b:1b:a4:b8:1a:63:f9:74:8f:ed:2d:8a:41:0c:2f:
       c2:1b:12:32:f0:d3:bf:a0:24:27:6c:fd:88:44:81:
       97:aa:e4:86:a6:3b:fc:a7:b8:bf:77:54:df:b3:27:
       c7:20:1f:6f:d1:7f:d7:fd:74:15:8b:d3:1c:e7:72:
       c9:f5:f8:ab:58:45:48:a9:9a:75:9b:5a:2c:05:32:
       16:2b:7b:62:18:e8:f1:42:bc:e2:c3:0d:77:84:68:
       9a:48:3e:09:5e:70:16:18:43:79:13:a8:c3:9c:3d:
       d0:d4:ca:3c:50:0b:88:5f:e3"""

N = int("".join(N.split()).replace(":", ""), 16)
g = 2 # A generator modulo N

I = 'carol'
a = randbelow(N)
A = pow(g, a, N)

r = remote('::1', 9999)

print("Sending I and A to Steve.")
payload = {
    "I": I,
    "A": A,
}
r.sendline(json.dumps(payload).encode())

print("Waiting for salt, B, and u from Steve.")
line = r.recvline()
data = json.loads(line)
s = bytes.fromhex(data["s"])
B = data["B"]
u = data["u"]

P = getpass()
x = client_x(s, P.encode())

S_c = pow(B, a + u * x, N)
K_c = hashlib.sha256(long_to_bytes(S_c)).digest()

print("Sending MAC of session key to Steve.")
mac = hmac.digest(K_c, s, 'sha256')
r.sendline(mac.hex().encode())

line = r.recvline(keepends=False)
print(line)

r.close()
