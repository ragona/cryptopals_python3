from Crypto import Random
from pals import utils
import random

def mt_stream_cipher(plaintext, seed):
    mt = utils.MT19937(seed)
    ciphertext = b''
    for b in plaintext:
        ciphertext += bytes([mt.extract_number() >> 24 ^ b])
    return ciphertext

#brute force recover seed within 16 bit number
def get_seed(ciphertext, known_plaintext):
    for i in range(2 << 16):
        print('seed {}'.format(i), end='\r')
        plaintext = mt_stream_cipher(ciphertext, i)
        if known_plaintext in plaintext:
            print()
            return i
    raise Exception("couldn't find seed in 2 << 16")

seed = random.randint(0, 2 << 16)
rand_plaintext = Random.get_random_bytes(random.randint(2, 6)) 
known_plaintext = b'A' * 14

#encrypt
ciphertext = mt_stream_cipher(rand_plaintext + known_plaintext, seed)
#decrypt
plaintext = mt_stream_cipher(ciphertext, seed)

#crack seed 
cracked_seed = get_seed(ciphertext, known_plaintext)
print('original: {}, cracked: {}'.format(seed, cracked_seed))

'''
Create the MT19937 stream cipher and break it
You can create a trivial stream cipher out of any PRNG; use it to 
generate a sequence of 8 bit outputs and call those outputs a keystream. 
XOR each byte of plaintext with each successive byte of keystream.

Write the function that does this for MT19937 using a 16-bit seed. Verify 
that you can encrypt and decrypt properly. This code should look similar 
to your CTR code.

Use your function to encrypt a known plaintext (say, 14 consecutive 'A' 
characters) prefixed by a random number of random characters.

From the ciphertext, recover the "key" (the 16 bit seed).

Use the same idea to generate a random "password reset token" using MT19937 
seeded from the current time.

Write a function to check if any given password token is actually the 
product of an MT19937 PRNG seeded with the current time.
'''