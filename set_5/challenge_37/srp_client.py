from pwn import *
import json
from getpass import getpass
from random import randrange
from pprint import pprint
from Crypto.Util.number import long_to_bytes, bytes_to_long
import hmac

# Pre-negotiated parameters.
N = int(
"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
"fffffffffffff", 16)
g = 2
k = 3

def client_x(salt, password):
    h = hashlib.sha256()
    h.update(long_to_bytes(salt))
    h.update(password)
    return bytes_to_long(h.digest())

def verifier(salt, password):
    x = client_x(salt, password)
    return pow(g, x, N)

def scramble(A, B):
    h = hashlib.sha256()
    h.update(long_to_bytes(A))
    h.update(long_to_bytes(B))
    return bytes_to_long(h.digest())

I = 'carol'
a = randrange(1, N)
A = pow(g, a, N)

r = remote('::1', 9999)

print("Sending I and A to Steve.")
payload = {
    "I": I,
    "A": A,
}
r.sendline(json.dumps(payload).encode())

print("Waiting for salt and B from Steve.")
line = r.recvline()
data = json.loads(line)
s = data["s"]
B = data["B"]

u = scramble(A, B)

P = getpass()
x = client_x(s, P.encode())

S_c = pow(B - k * pow(g, x, N), a + u * x, N)
K_c = hashlib.sha256(long_to_bytes(S_c)).digest()

print("Sending MAC of session key to Steve.")
mac = hmac.digest(K_c, long_to_bytes(s), 'sha256')
r.sendline(mac)

line = r.recvline(keepends=False)
print(line)

r.close()
