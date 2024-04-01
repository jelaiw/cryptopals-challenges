"""
An example SRP authentication

WARNING: Do not use for real cryptographic purposes beyond testing.
WARNING: This below code misses important safeguards. It does not check A, B, and U are not zero.

based on http://srp.stanford.edu/design.html
"""

import hashlib
import random

# Note: str converts as is, str([1,2,3,4]) will convert to "[1,2,3,4]"
def H(*args) -> int:
    """A one-way hash function."""
    a = ":".join(str(a) for a in args)
    return int(hashlib.sha256(a.encode("utf-8")).hexdigest(), 16)

def cryptrand(n: int = 1024):
    return random.SystemRandom().getrandbits(n) % N

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

k = H(N, g)

F = '#0x' # Format specifier

print("#. H, N, g, and k are known beforehand to both client and server:")
print(f'{H = }\n{N = :{F}}\n{g = :{F}}\n{k = :{F}}')

print("\n0. server stores (I, s, v) in its password database")

# The server must first generate the password verifier
I = "person"        # Username
p = "password1234"  # Password
s = cryptrand(64)   # Salt for the user
x = H(s, I, p)      # Private key
v = pow(g, x, N)    # Password verifier

print(f'{I = }\n{p = }\n{s = :{F}}\n{x = :{F}}\n{v = :{F}}')

# 0. server stores(I, s, v) in its password database
# I = 'person'
# p = 'password1234'
# s = 0x67bc8932cfd26a49
# x = 0x98a4bce8dde877762a90222f1a1161eba9248590a47eb83aa9e5bd7ecda5368d
# v = 0xa7e2038e675d577ac0f318999cab67bba7ec2daf45d2d09f7911b1b78d2fc7f963cd0ac8f17851e0516f059e453672c3b70fcecf5f6843180b271abdd01f552ccda7b24fe4719336409cbc1352f8517be651b8935cc0b74ff2819fa07a3f031537d4cfd9f8df7b788a5f2f88e1cd4106b35c38b3d7205a

# <demo> --- stop ---

print("\n1. client sends username I and public ephemeral value A to the server")
a = cryptrand()
A = pow(g, a, N)
print(f"{I = }\n{A = :{F}}")  # client->server (I, A)

# 1. client sends username I and public ephemeral value A to the server
# I = 'person'
# A = 0x678556a7e76581e051af656e8cee57ae46df43f1fce790f7750a3ec5308a85da4ec4051e5cb74d3e463685ee975a2747cf49035be67c931b56e793f23ea3524af8909dcfbc8675d872361025bf884778587ac49454a57c53a011ac2be2839bfb51bf7847a49a483aba870dc7a8b467a81cec91b8ae7813

# <demo> --- stop ---

print("\n2. server sends user's salt s and public ephemeral value B to client")
b = cryptrand()
B = (k * v + pow(g, b, N)) % N
print(f"{s = :{F}}\n{B = :{F}}")  # server->client (s, B)

# 2. server sends user's salt s and public ephemeral value B to client
# s = 0x67bc8932cfd26a49
# B = 0xb615a0a5ea6abf138077bbd869f6a8da37dfc0b7e06a9f5fac5c1e4109c6302cb3e94dcc2cc76da7b3d87d7e9b68a1db998ab239cfde609f3f7a1ece4a491ce3d9a665c20cf4e4f06730daaa8f52ed61e45bbb67cdc337bf648027ffa7f0f215d5ebe43f9f51832518f1142266aae0dfa960e0082b5154

# <demo> --- stop ---

print("\n3. client and server calculate the random scrambling parameter")
u = H(A, B)  # Random scrambling parameter
print(f"{u = :{F}}")

# 3. client and server calculate the random scrambling parameter
# u = 0x796b07e354c04f672af8b76a46560655086355a9bbce11361f01b45d991c0c52

# <demo> --- stop ---

print("\n4. client computes session key")
x = H(s, I, p)
S_c = pow(B - k * pow(g, x, N), a + u * x, N)
K_c = H(S_c)
print(f"{S_c = :{F}}\n{K_c = :{F}}")

# 4. client computes session key
# S_c = 0x699170aff6e9f08ed09a1dff432bf0605b8bcba05aadcaeea665757d06dbda4348e211d16c10ef4678585bcb2809a83c62b6c19d97901274ddafd4075f90604c06baf036af587af8540342b47867eaa22b9ca5e35ac14c8e85a0c4e623bd855828dffd513cea4d829c407137a0dd81ab4cde8a904c45cc
# K_c = 0x43f8df6e1d2ba762948c8316db5bf03a7af49391742f5f51029630711c1671e

# <demo> --- stop ---

print("\n5. server computes session key")
S_s = pow(A * pow(v, u, N), b, N)
K_s = H(S_s)
print(f"{S_s = :{F}}\n{K_s = :{F}}")

# 5. server computes session key
# S_s = 0x699170aff6e9f08ed09a1dff432bf0605b8bcba05aadcaeea665757d06dbda4348e211d16c10ef4678585bcb2809a83c62b6c19d97901274ddafd4075f90604c06baf036af587af8540342b47867eaa22b9ca5e35ac14c8e85a0c4e623bd855828dffd513cea4d829c407137a0dd81ab4cde8a904c45cc
# K_s = 0x43f8df6e1d2ba762948c8316db5bf03a7af49391742f5f51029630711c1671e

# <demo> --- stop ---

print("\n6. client sends proof of session key to server")
M_c = H(H(N) ^ H(g), H(I), s, A, B, K_c)
print(f"{M_c = :{F}}")
# client->server (M_c) ; server verifies M_c

# 6. client sends proof of session key to server
# M_c = 0x75500df4ea36e06406ac1f8a8241429b8e90a8cba3adda3405c07f19ea3101e8

# <demo> --- stop ---

print("\n7. server sends proof of session key to client")
M_s = H(A, M_c, K_s)
print(f"{M_s = :{F}}")
# server->client (M_s) ;  client verifies M_s

# 7. server sends proof of session key to client
# M_s = 0x182ed24d1ad2fb55d2268c46b42435d1ef02e0fc49f647c03dab8b2a48b0bd3d
