from Crypto.Util import number
from os import urandom
from binascii import hexlify, unhexlify

def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big') 

def int_to_bytes(i):
    return i.to_bytes((i.bit_length() + 7) // 8, 'big')

class RSA:

    def generate_keys(key_size=1024, e=65537):
        #d of 1 indicates that the number didn't inverse 
        #appropriately, so we try again until it works.
        #this doesn't happen (often?) when e is 65537, but
        #does happen often when e is 3. 
        d = 1
        while d == 1:
            #this block ensures that n is the right size
            n = 0
            while n.bit_length() != key_size:
                p = number.getPrime(key_size // 2, urandom)
                q = number.getPrime(key_size // 2, urandom)
                n = p * q
            et = (p-1)*(q-1)
            d = number.inverse(e, et)
        return (e, n), (d, n) #public, private

    def encrypt(m, key):
        return pow(bytes_to_int(m), key[0], key[1]) #e, n

    def decrypt(m, key):
        c = pow(m, key[0], key[1]) #d, n
        return int_to_bytes(c)
