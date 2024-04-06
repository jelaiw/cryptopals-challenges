from Crypto.Util.number import long_to_bytes, bytes_to_long
import hashlib

def client_x(salt, password):
    h = hashlib.sha256()
    h.update(salt)
    h.update(password)
    return bytes_to_long(h.digest())

def scramble(A, B):
    h = hashlib.sha256()
    h.update(long_to_bytes(A))
    h.update(long_to_bytes(B))
    return bytes_to_long(h.digest())
