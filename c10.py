import binascii
import base64
from Crypto.Cipher import AES
from Crypto import Random
from pals import utils

a = utils.pad(b"YELLOW SUBMARINE", 16)
b = utils.aes_ecb_encrypt(a, b'YELLOW SUBMARINE', b'00000')
c = utils.aes_ecb_decrypt(b, b'YELLOW SUBMARINE', b'00000')

block_size = 16
key = b'YELLOW SUBMARINE'
iv = b'0' * block_size

with open('files/c10.txt', 'rb') as f:
    data = b"banana"#f.read()
    enc = utils.aes_cbc_encrypt(data, key, iv)
    dec = utils.aes_cbc_decrypt(enc, key, iv)
    for line in dec.splitlines():
        print(line)





'''
Implement CBC mode
CBC mode is a block cipher mode that allows us to encrypt 
irregularly-sized messages, despite the fact that a block 
cipher natively only transforms individual blocks.

In CBC mode, each ciphertext block is added to the next 
plaintext block before the next call to the cipher core.

The first plaintext block, which has no associated previous 
ciphertext block, is added to a "fake 0th ciphertext block" 
called the initialization vector, or IV.

Implement CBC mode by hand by taking the ECB function you 
wrote earlier, making it encrypt instead of decrypt (verify 
this by decrypting whatever you encrypt to test), and using 
your XOR function from the previous exercise to combine them.

The file here is intelligible (somewhat) when CBC decrypted against 
"YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)
'''