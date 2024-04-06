from pwn import *
import json
from secrets import randbelow
from Crypto.Util.number import long_to_bytes
import hmac
from srp_helper import scramble

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

# Client registration
s = long_to_bytes(0x9eb1f741901d0695) # Yeesh.
v = 1333335891663171031586462236725377343462800564467112949994046886030083987743532811847918401097711299084702584260572729345359832923914616793551454854761795001778010197333817271850556902727570233670332428113846766172887343179183889298033394015312427243312763196545734807534388975099555538821274290218636014064345066426645833225905817239672186292473215272452995074988907009139431434140576838284761256910079348416616309107594619898626887295193667892505051147764828621

l = listen(9999)
_ = l.wait_for_connection()

b = randbelow(N)
B = k * v + pow(g, b, N)
B = B % N

print("Waiting for I and A from Carol.")
line = l.recvline()
data = json.loads(line)
if "I" in data and data["I"] == 'carol' and "A" in data:
    payload = {
        "s": s.hex(),
        "B": B,
    }
    l.sendline(json.dumps(payload).encode())
else:
    print(line)
    exit(1)

A = data["A"]
u = scramble(A, B)

S_s = pow(A * pow(v, u, N), b, N)
K_s = hashlib.sha256(long_to_bytes(S_s)).digest()

print("Waiting for MAC from Carol.")
line = l.recvline(keepends=False)
mac_bytes = bytes.fromhex(line.decode())
if hmac.compare_digest(mac_bytes, hmac.digest(K_s, s, 'sha256')):
    l.sendline(b"OK")
else:
    l.sendline(b"Nein")

l.close()
