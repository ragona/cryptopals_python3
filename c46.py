from math import log, ceil
from base64 import b64decode
from pals.RSA import RSA
from pals.utils import bytes_to_int, int_to_bytes

def is_odd_oracle(private_key, ciphertext):
    return bytes_to_int(RSA.decrypt(ciphertext, private_key)) & 1

def parity_decrypt(c, pub):
    low = 0
    high = n
    e, n = pub
    mult = pow(2, e, n)
    for _ in range(ceil(log(n, 2))): 
        c = c * mult
        if is_odd_oracle(int_to_bytes(c)):
            low = (low + high) / 2
        else:
            high = (low + high) / 2


plain = b64decode(b'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==')
msg = b'secret message'
pub, pri = RSA.generate_keys()
ciphertext = RSA.encrypt(msg, pub)
print(ciphertext)
is_odd = is_odd_oracle(pri, ciphertext)

print(is_odd)
'''
RSA parity oracle
When does this ever happen?
This is a bit of a toy problem, but it's very helpful for understanding 
what RSA is doing (and also for why pure number-theoretic encryption is 
terrifying). Trust us, you want to do this before trying the next 
challenge. Also, it's fun.

Generate a 1024 bit RSA key pair.

Write an oracle function that uses the private key to answer the question 
"is the plaintext of this message even or odd" (is the last bit of the 
message 0 or 1). Imagine for instance a server that accepted RSA-encrypted 
messages and checked the parity of their decryption to validate them, and 
spat out an error if they were of the wrong parity.

Anyways: function returning true or false based on whether the decrypted 
plaintext was even or odd, and nothing else.

Take the following string and un-Base64 it in your code (without looking 
at it!) and encrypt it to the public key, creating a ciphertext:

VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==
With your oracle function, you can trivially decrypt the message.

Here's why:

RSA ciphertexts are just numbers. You can do trivial math on them. You can 
for instance multiply a ciphertext by the RSA-encryption of another number; 
the corresponding plaintext will be the product of those two numbers.
If you double a ciphertext (multiply it by (2**e)%n), the resulting plaintext 
will (obviously) be either even or odd.
If the plaintext after doubling is even, doubling the plaintext didn't wrap 
the modulus --- the modulus is a prime number. That means the plaintext is 
less than half the modulus.
You can repeatedly apply this heuristic, once per bit of the message, checking 
your oracle function each time.

Your decryption function starts with bounds for the plaintext of [0,n].

Each iteration of the decryption cuts the bounds in half; either the upper 
bound is reduced by half, or the lower bound is.

After log2(n) iterations, you have the decryption of the message.

Print the upper bound of the message as a string at each iteration; you'll see 
the message decrypt "hollywood style".

Decrypt the string (after encrypting it to a hidden private key) above.
'''