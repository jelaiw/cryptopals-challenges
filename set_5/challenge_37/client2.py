from pwn import *
import json
from Crypto.Util.number import long_to_bytes
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

I = 'carol'
A = N

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
s = bytes.fromhex(data['s'])

S_c = 0
K_c = hashlib.sha256(long_to_bytes(S_c)).digest()

print("Sending MAC of session key to Steve.")
mac = hmac.digest(K_c, s, 'sha256')
r.sendline(mac.hex().encode())

line = r.recvline(keepends=False)
print(line)

r.close()
