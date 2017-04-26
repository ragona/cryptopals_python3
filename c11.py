import binascii
import random
from Crypto import Random
from pals import utils

def encryption_oracle(data):
    key = Random.get_random_bytes(16)
    randbytes = lambda: Random.get_random_bytes(random.randrange(5, 10))
    data = randbytes() + data + randbytes()
    ciphertext = bytes()
    if random.getrandbits(1):
        print('ecb')
        ciphertext = utils.aes_ecb_encrypt(data, key)
    else:
        print('cbc')
        ciphertext = utils.aes_cbc_encrypt(data, key, b'0' * 16)
    return ciphertext

#works as long as we know there is repeating input
a = encryption_oracle(b"a" * 50)
is_ecb = utils.detect_ecb(a, 16)
print(is_ecb)

'''
An ECB/CBC detection oracle
Now that you have ECB and CBC working:

Write a function to generate a random AES
key; that's just 16 random bytes.

Write a function that encrypts data under an
unknown key --- that is, a function that generates
a random key and encrypts under it.

The function should look like:

encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]
Under the hood, have the function append 5-10 bytes
(count chosen randomly) before the plaintext and 5-10
bytes after the plaintext.

Now, have the function choose to encrypt under ECB
1/2 the time, and under CBC the other half (just
use random IVs each time for CBC). Use rand(2) to
decide which to use.

Detect the block cipher mode the function is using
each time. You should end up with a piece of code
that, pointed at a block box that might be encrypting
ECB or CBC, tells you which one is happening.
'''