'''
Implement repeating-key XOR

Here is the opening stanza of an important work of the English language:

Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal

Encrypt it, under the key "ICE", using repeating-key XOR.

In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.

It should come out to:

0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
'''

import binascii

key = b"ICE"
phrase = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

def encrypt(p, k):
    return binascii.hexlify(bytes([p[i] ^ k[i % len(k)] for i in range(len(p))]))

print(encrypt(phrase, key)) 

#okay, the resulting string ALMOST matches the expected result 
#but the wanted result has a newline in it, and I can't figure out why

# python 2
# def encrypt(p, k):
#     output = ""
#     for i, c in enumerate(p):
#         output += binascii.hexlify(chr(ord(c) ^ ord(k[i % len(k)])))
#     return output

