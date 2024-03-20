from pwn import *
import json
from random import randrange
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

# Client registration
s = 439530352780665893516122517780751541091162226213638861907411881063797542005018568117210589020438188848205141442242392323554443054097844335270612016805240947615839861899243795626743154645526934224011584135571396034913374637737914828624534837908556813724664857343889752943425799443415765767563869237981072517431732912863466384075356700634830839776792951768516438858163652307359805300508022161471067342018906327210375742862139645363124625694748345366985509150560107
v = 1290407028566102901343375370458303158357319861567441871361819963827896973112756529526437691345631692404123839915294104630752120040360084992957846679165882341680289605688140503657993105045316699568846358595861674349206561858784161554870868477987086770579391139719698601195015152461074281515162872939788466835100011788332743921904859645549447014029099190967043201981279816332059183372580207385701409117470219346464324488958007162320200563992002429069231621799405504

def scramble(A, B):
    h = hashlib.sha256()
    h.update(long_to_bytes(A))
    h.update(long_to_bytes(B))
    return bytes_to_long(h.digest())

l = listen(9999)
_ = l.wait_for_connection()

b = randrange(1, N)
B = k * v + pow(g, b, N)
B = B % N

print("Waiting for I and A from Carol.")
line = l.recvline()
data = json.loads(line)
if "I" in data and data["I"] == 'carol' and "A" in data:
    payload = {
        "s": s,
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
if hmac.compare_digest(line, hmac.digest(K_s, long_to_bytes(s), 'sha256')):
    l.sendline(b"OK")
else:
    l.sendline(b"Nein")

l.close()
