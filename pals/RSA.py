from Crypto.Util import number
from os import urandom
from binascii import hexlify, unhexlify

def bytes_to_int(b):
    return int(hexlify(b), 16) 

def bytes_from_int(i):
    return unhexlify(hex(i)[2:])

class RSA:

    def generate_keys(key_size):
        p = number.getPrime(key_size // 2, urandom)
        q = number.getPrime(key_size // 2, urandom)
        n = p * q
        et = (p-1)*(q-1)
        e = 65537 #TODO: should this be random? need to research.
        d = number.inverse(e, et)
        return (e, n), (d, n) #public, private

    def encrypt(m, key):
        return pow(bytes_to_int(m), key[0], key[1])#e, n)

    def decrypt(m, key):
        c = pow(m, key[0], key[1])#d, n)
        return bytes_from_int(c)
