from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from pals import utils
import random
import base64

##===serverside====
random_key = Random.get_random_bytes(16)
iv = Random.get_random_bytes(16)
strs = [
    b'YELLOW SUBMARINEYELLOW SUBMARIN'
    # b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
    # b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
    # b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
    # b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
    # b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
    # b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
    # b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
    # b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
    # b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
    # b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93',
]

def black_box():
    s = utils.pad(strs[random.randrange(0, len(strs))], 16)
    aes = AES.new(random_key, AES.MODE_CBC, iv)
    return aes.encrypt(s)

def oracle(ciphertext):
    return is_padding_valid(decrypt(ciphertext))

def decrypt(ciphertext):
    return AES.new(random_key, AES.MODE_CBC, iv).decrypt(ciphertext)
    
def is_padding_valid(plaintext):
    # print(plaintext)
    try:
        utils.unpad(plaintext)
        return True
    except:
        return False
#==================

def solve_block(block, block_size=16):
    #intermediate bytes
    intermediate = bytearray(block_size)
    #the buffer we'll be sending into the oracle
    test = bytearray(block_size) + block
    #solve one byte at a time, from the back
    for byte_num in reversed(range(block_size)):
        #test each byte value
        for i in range(256):
            #set the byte we're solving to the test option
            test[byte_num] = i
            #send the test into the oracle
            if not oracle(bytes(test)):
                continue #failure case
            #success case
            pad_size = block_size - byte_num
            intermediate[byte_num] = test[byte_num] ^ pad_size 
            for j in range(byte_num, block_size):
                test[j] ^= pad_size
                test[j] ^= pad_size + 1
            break
    return intermediate

def solve(ciphertext):
    #just solve the last block for now
    b1 = ciphertext[-32:-16]
    b2 = ciphertext[-16:]
    a = solve_block(b2) 
    print(xor(b1, a))

def xor(a, b):
    return b''.join([bytes([a[i] ^ b[i]]) for i in range(len(a))])

print(
    solve(black_box())
)
'''
The CBC padding oracle
This is the best-known attack on modern block-cipher cryptography.

Combine your padding code and your CBC code to write two functions.

The first function should select at random one of the following 10 strings:

MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
... generate a random AES key (which it should save for all future encryptions), 
pad the string out to the 16-byte AES block size and CBC-encrypt it under that 
key, providing the caller the ciphertext and IV.

The second function should consume the ciphertext produced by the first function, 
decrypt it, check its padding, and return true or false depending on whether the 
padding is valid.

What you're doing here.
This pair of functions approximates AES-CBC encryption as its deployed serverside 
in web applications; the second function models the server's consumption of an 
encrypted session token, as if it was a cookie.

It turns out that it's possible to decrypt the ciphertexts provided by the first 
function.

The decryption here depends on a side-channel leak by the decryption function. 
The leak is the error message that the padding is valid or not.

You can find 100 web pages on how this attack works, so I won't re-explain it. 
What I'll say is this:

The fundamental insight behind this attack is that the byte 01h is valid padding, 
and occur in 1/256 trials of "randomized" plaintexts produced by decrypting a 
tampered ciphertext.

02h in isolation is not valid padding.

02h 02h is valid padding, but is much less likely to occur randomly than 01h.

03h 03h 03h is even less likely.

So you can assume that if you corrupt a decryption AND it had valid padding, 
you know what that padding byte is.

It is easy to get tripped up on the fact that CBC plaintexts are "padded". 
Padding oracles have nothing to do with the actual padding on a CBC plaintext. 
It's an attack that targets a specific bit of code that handles decryption. You 
can mount a padding oracle on any CBC block, whether it's padded or not.
'''