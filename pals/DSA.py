from hashlib import sha1
from Crypto.Random import random
from Crypto.Util.number import inverse

p = int(('800000000000000089e1855218a0e7dac38136ffafa72eda7'
         '859f2171e25e65eac698c1702578b07dc2a1076da241c76c6'
         '2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe'
         'ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2'
         'b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87'
         '1a584471bb1'), 16)

q = int('f4f47f05794b256174bba6e9b396a7707e563c5b', 16)

g = int(('5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119'
         '458fef538b8fa4046c8db53039db620c094c9fa077ef389b5'
         '322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047'
         '0f5b64c36b625a097f1651fe775323556fe00b3608c887892'
         '878480e99041be601a62166ca6894bdd41a7054ec89f756ba'
         '9fc95302291') , 16)

def H(message):
  return int.from_bytes(sha1(message).digest(), 'big') 

class DSA:
    def generate_user_key_pair():
        x = random.randint(2, 2<<64) #how big should this number be? 
        y = pow(g, x, p)
        return ((p,q,g,y), (p,q,g,x)) #public / private 

    def sign(message, private):
        p,q,g,x = private
        h = H(message)
        while True:
            k = random.randint(0, 1<<16)
            r = pow(g, k, p) % q
            if r == 0:
                continue
            i = inverse(k, q)
            s = i*(h+r*x) % q
            if s != 0:
                break
        return (r, s)

    def verify(message, signature, public):
        p,q,g,y = public
        r, s = signature
        h = H(message)
        w = inverse(s, q)
        u1 = h * w % q 
        u2 = r * w % q
        v = (pow(g, u1, p) * pow(y, u2, p) % p) % q
        return v == r
