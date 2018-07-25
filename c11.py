import random
from Crypto import Random
from pals.ciphers import aes_cbc_encrypt, aes_ecb_encrypt
from pals.utils import detect_ecb


def encryption_oracle(data):
    key = Random.get_random_bytes(16)
    data = randbytes() + data + randbytes()
    use_ecb = random.getrandbits(1)
    if use_ecb:
        ciphertext = aes_ecb_encrypt(data, key)
    else:
        ciphertext = aes_cbc_encrypt(data, key, b'0' * 16)

    # we return whether we used ecb so we can error if we got it wrong
    return ciphertext, use_ecb


def randbytes():
    return Random.get_random_bytes(random.randrange(5, 10))


def main():
    ciphertext, is_ecb = encryption_oracle(b"a" * 50)
    ecb_detected = detect_ecb(ciphertext)
    if ecb_detected != is_ecb:
        raise Exception("ECB detection failed")


if __name__ == '__main__':
    main()

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