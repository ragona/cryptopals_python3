import base64
from pals import utils 
from Crypto import Random

key = Random.get_random_bytes(16)
nonce = Random.get_random_bytes(8)

def edit(ciphertext, key, offset, newtext):
    plaintext = utils.ctr(ciphertext, key, nonce)
    plaintext = plaintext[:offset] + newtext + plaintext[offset + len(newtext):]
    return utils.ctr(plaintext, key, nonce)

def sample_api(ciphertext, offset, newtext):
    return edit(ciphertext, key, offset, newtext)

with open('files/c25.txt', 'rb') as f:
    plaintext = utils.aes_ecb_decrypt(base64.b64decode(f.read()), b'YELLOW SUBMARINE')
    ciphertext = utils.ctr(plaintext, key, nonce)
    #since we control the offset and can overwrite
    #just pass the ciphertext back in with NO offset
    #and it'll just return the plaintext back since 
    #ctr doesn't encrypt plaintext, it just encrypts
    #nonce plus counter and xors that against the plaintext
    print(
        sample_api(ciphertext, 0, ciphertext)
    )

'''
Break "random access read/write" AES CTR
Back to CTR. Encrypt the recovered plaintext from this file 
(the ECB exercise) under CTR with a random key (for this exercise 
the key should be unknown to you, but hold on to it).

Now, write the code that allows you to "seek" into the ciphertext, 
decrypt, and re-encrypt with different plaintext. Expose this as 
a function, like, "edit(ciphertext, key, offset, newtext)".

Imagine the "edit" function was exposed to attackers by means of an 
API call that didn't reveal the key or the original plaintext; the 
attacker has the ciphertext and controls the offset and "new text".

Recover the original plaintext.

Food for thought.
A folkloric supposed benefit of CTR mode is the ability to easily 
"seek forward" into the ciphertext; to access byte N of the ciphertext, 
all you need to be able to do is generate byte N of the keystream. 
Imagine if you'd relied on that advice to, say, encrypt a disk.
'''