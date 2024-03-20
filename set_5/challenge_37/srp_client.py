from pwn import *
import json
from getpass import getpass
from random import randrange
from pprint import pprint
from Crypto.Util.number import long_to_bytes, bytes_to_long

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

payload = {
    "I": I,
    "A": A,
}

r = remote('::1', 9999)
r.sendline(json.dumps(payload).encode())

line = r.recvline()
data = json.loads(line)

password = getpass()
