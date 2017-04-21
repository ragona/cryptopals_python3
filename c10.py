import binascii
from Crypto.Cipher import AES
from Crypto import Random

block_size = 16

with open('files/c10.txt', 'rb') as f:
    d = f.read()

    iv = '0' * block_size
    result = bytearray()
    for i in range(0, len(d), block_size):
        aes = AES.new(b'YELLOW SUBMARINE', AES.MODE_ECB, iv)
        block = d[i : i + block_size]
        cipher = aes.decrypt(block)
        iv = cipher
        result.append(result)
    print(result)




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