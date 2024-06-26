from Crypto.Util.number import bytes_to_long
import hashlib

def client_x(salt, password):
    h = hashlib.sha256()
    h.update(salt)
    h.update(password)
    return bytes_to_long(h.digest())
