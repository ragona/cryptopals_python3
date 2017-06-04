'''
A few notes: 
- I got my own invmod and e_gcd working by following 
wikipedia pseudocode, but it makes my brain hurt so I 
swapped it out with the pycrypto number library version 
for brevity. 
- Using an e of 3 means you need to try different 
primes until you get one that will work out to be properly 
inverted, so I'm using 2**16+1 which I'm told is commonly 
used by RSA. 
- I don't quite get how you're supposed to 
encapsulate the keys -- when I see RSA keys they're not two 
numbers, they're just one giant b64 blob. Is (e, n) 
contained within there and labeled somehow?  
'''

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

msg = b'secret message'
pub, pri = RSA.generate_keys(1024)
ciphertext = RSA.encrypt(msg, pub)
plaintext = RSA.decrypt(ciphertext, pri)

print(plaintext == msg)
'''
Implement RSA
There are two annoying things about implementing RSA. Both of 
them involve key generation; the actual encryption/decryption 
in RSA is trivial.

First, you need to generate random primes. You can't just agree 
on a prime ahead of time, like you do in DH. You can write this 
algorithm yourself, but I just cheat and use OpenSSL's BN library 
to do the work.

The second is that you need an "invmod" operation (the 
multiplicative inverse), which is not an operation that is wired 
into your language. The algorithm is just a couple lines, but I 
always lose an hour getting it to work.

I recommend you not bother with primegen, but do take the time to 
get your own EGCD and invmod algorithm working.

Now:

Generate 2 random primes. We'll use small numbers to start, so you 
can just pick them out of a prime table. Call them "p" and "q".
Let n be p * q. Your RSA math is modulo n.
Let et be (p-1)*(q-1) (the "totient"). You need this value only for 
keygen.
Let e be 3.
Compute d = invmod(e, et). invmod(17, 3120) is 2753.
Your public key is [e, n]. Your private key is [d, n].
To encrypt: c = m**e%n. To decrypt: m = c**d%n
Test this out with a number, like "42".
Repeat with bignum primes (keep e=3).
Finally, to encrypt a string, do something cheesy, like convert the 
string to hex and put "0x" on the front of it to turn it into a number. 
The math cares not how stupidly you feed it strings.
'''