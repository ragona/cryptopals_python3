from Crypto.Cipher import AES
from Crypto import Random
import base64


s = b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
key = b'YELLOW SUBMARINE'

def ctr(buffer):
    output = bytes()
    nonce = bytes(8)
    for i in range(len(buffer) // 16 + 1):
        counter = (i).to_bytes(8, byteorder='little')
        keystream = AES.new(key, AES.MODE_ECB).encrypt(nonce + counter)
        block = buffer[i * 16 : i * 16 + 16]
        output += xor(block, keystream)
    return output

def xor(a, b):
    return b''.join([bytes([a[i] ^ b[i]]) for i in range(len(a))])

print(
    ctr(base64.b64decode(s))
)

a = ctr(b'foo')
b = ctr(a)
c = ctr(b)
d = ctr(c)

print(a)
print(b)
print(c)
print(d)


'''
Implement CTR, the stream cipher mode
The string:

L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==
... decrypts to something approximating English in CTR mode, which is an AES 
block cipher mode that turns AES into a stream cipher, with the following parameters:

      key=YELLOW SUBMARINE
      nonce=0
      format=64 bit unsigned little endian nonce,
             64 bit little endian block count (byte count / 16)
CTR mode is very simple.

Instead of encrypting the plaintext, CTR mode encrypts a running counter, producing 
a 16 byte block of keystream, which is XOR'd against the plaintext.

For instance, for the first 16 bytes of a message with these parameters:

keystream = AES("YELLOW SUBMARINE",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
... for the next 16 bytes:

keystream = AES("YELLOW SUBMARINE",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00")
... and then:

keystream = AES("YELLOW SUBMARINE",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00")
CTR mode does not require padding; when you run out of plaintext, you just stop XOR'ing 
keystream and stop generating keystream.

Decryption is identical to encryption. Generate the same keystream, XOR, and recover 
the plaintext.

Decrypt the string at the top of this function, then use your CTR function to encrypt 
and decrypt other things.
'''