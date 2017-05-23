from Crypto import Random 
from pals import utils

rand_key = Random.get_random_bytes(16)

#receiving service
def black_box(user_input):
    return utils.aes_cbc_encrypt(user_input, rand_key, rand_key) #use key as IV

def parse(cookie):
    return utils.aes_cbc_decrypt(cookie, rand_key, rand_key) #use key as IV

#attacker
#initial valid cookie
message = black_box(b'YELLOW SUBMARINE'*3)
#modified cookie with first block twice and empty padding in middle
modified = message[:16] + bytes(16) + message[:16]
#the 'error return' text that would be returned in a debug message on parsing non-ascii chars
parsed = parse(modified) 
#the extracted key (block 1 ^ block 3)
key = b''.join([bytes([i[0] ^ i[1]]) for i in zip(parsed[:16], parsed[-16:])])
#test
print('key matches:', key == rand_key)
print('extracted key:', key)

'''
Recover the key from CBC with IV=Key
Take your code from the CBC exercise and modify it so that it 
repurposes the key for CBC encryption as the IV.

Applications sometimes use the key as an IV on the auspices that 
both the sender and the receiver have to know the key already, and 
can save some space by using it as both a key and an IV.

Using the key as an IV is insecure; an attacker that can modify 
ciphertext in flight can get the receiver to decrypt a value that 
will reveal the key.

The CBC code from exercise 16 encrypts a URL string. Verify each 
byte of the plaintext for ASCII compliance (ie, look for high-ASCII 
values). Noncompliant messages should raise an exception or return 
an error that includes the decrypted plaintext (this happens all 
the time in real systems, for what it's worth).

Use your code to encrypt a message that is at least 3 blocks long:

AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3
Modify the message (you are now the attacker):

C_1, C_2, C_3 -> C_1, 0, C_1
Decrypt the message (you are now the receiver) and raise the 
appropriate error if high-ASCII is found.

As the attacker, recovering the plaintext from the error, extract 
the key:

P'_1 XOR P'_3
'''