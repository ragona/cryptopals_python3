from Crypto import Random
from pals import utils
import base64

b64unknown = b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
rand_key = Random.get_random_bytes(16)
unknown = base64.b64decode(b64unknown)

def solve_unknown():
    #get blocksize
    blocksize = 0
    for i in range(64):
        known = (b'A' * i) * 2
        plaintext = known + unknown
        enc = utils.aes_ecb_encrypt(plaintext, rand_key, b'0'*16)
        if utils.detect_ecb(enc):
            blocksize = i
            break
    #asdasd
    solved = b''
    pad = b'A' * blocksize
    for i in range(32):
        pad = b'A' * (blocksize - 1 - len(solved))
        cipher = utils.aes_ecb_encrypt(pad + unknown, rand_key, b'0'*16)
        print(i, pad, len(pad))
        results = {}
        for j in range(0,255):
            test = utils.aes_ecb_encrypt(pad + solved + bytes([j]) + unknown, rand_key, b'0'*16)    
            block = test[0:blocksize]
            results[block] = bytes([j])
        if cipher[0:blocksize] in results:
            solved += results[cipher[0:blocksize]]

    print(solved)

solve_unknown()

'''
Byte-at-a-time ECB decryption (Simple)
Copy your oracle function to a new function that encrypts 
buffers under ECB mode using a consistent but unknown key 
(for instance, assign a single random key, once, to a global
variable).

Now take that same function and have it append to the 
plaintext, BEFORE ENCRYPTING, the following string:

Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK

Spoiler alert.
Do not decode this string now. Don't do it.

Base64 decode the string before appending it. Do not base64 
decode the string by hand; make your code do it. The point 
is that you don't know its contents.

What you have now is a function that produces:

AES-128-ECB(your-string || unknown-string, random-key)
It turns out: you can decrypt "unknown-string" with repeated 
calls to the oracle function!

Here's roughly how:

Feed identical bytes of your-string to the function 1 at a time 
--- start with 1 byte ("A"), then "AA", then "AAA" and so on. 
Discover the block size of the cipher. You know it, but do this 
step anyway.

Detect that the function is using ECB. You already know, but 
do this step anyways.

Knowing the block size, craft an input block that is exactly 1 
byte short (for instance, if the block size is 8 bytes, make 
"AAAAAAA"). Think about what the oracle function is going to put 
in that last byte position.

Make a dictionary of every possible last byte by feeding different 
strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", 
"AAAAAAAC", remembering the first block of each invocation.
Match the output of the one-byte-short input to one of the entries 
in your dictionary. You've now discovered the first byte of 
unknown-string.

Repeat for the next byte.
'''