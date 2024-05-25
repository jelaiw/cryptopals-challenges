from Crypto.Util.number import getPrime, bytes_to_long

NUM_BITS = 64
def encrypt(plaintext):
    p = getPrime(NUM_BITS)
    q = getPrime(NUM_BITS)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 3
    d = pow(e, -1, phi)
    assert e * d % phi == 1

    return pow(bytes_to_long(plaintext), e, n), n

message = b'attack at dawn'

count = 0
while count < 3:
    try:
        c, n = encrypt(message)
        print(c, n)
        count += 1
    except ValueError:
        continue
