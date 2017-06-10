from Crypto.Util.number import inverse
from pals.RSA import RSA, bytes_from_int, bytes_to_int
import json, time, hashlib

public, private = RSA.generate_keys()
seen = set()

def generate_blob(ssn):
    blob = {
        'time': int(time.time()),
        'ssn': ssn
    }
    return json.dumps(blob) 

def encrypt_blob(blob):
    return RSA.encrypt(blob.encode('utf-8'), public)

def decypher_blob(ciphertext):
    msg = RSA.decrypt(ciphertext, private)
    hsh = hashlib.sha1(msg).digest()
    if hsh in seen:
        return 'nope'
    seen.add(hsh)
    return msg

blob = generate_blob('555-55-5555')
C = encrypt_blob(blob)
E = public[0]
N = public[1] 
S = 2<<32 % N  

a = decypher_blob(C)
a = bytes_to_int(a)
nC = (pow(S, E, N) * C) % N
nP = decypher_blob(nC)
P = (bytes_to_int(nP) // S) % N

print('original:', blob)
print('recovered:', bytes_from_int(P))

'''
Implement unpadded message recovery oracle
Nate Lawson says we should stop calling it "RSA padding" a
nd start calling it "RSA armoring". Here's why.

Imagine a web application, again with the Javascript 
encryption, taking RSA-encrypted messages which (again: 
Javascript) aren't padded before encryption at all.

You can submit an arbitrary RSA blob and the server will 
return plaintext. But you can't submit the same message 
twice: let's say the server keeps hashes of previous messages 
for some liveness interval, and that the message has an 
embedded timestamp:

{
  time: 1356304276,
  social: '555-55-5555',
}
You'd like to capture other people's messages and use the 
server to decrypt them. But when you try, the server takes 
the hash of the ciphertext and uses it to reject the request. 
Any bit you flip in the ciphertext irrevocably scrambles the 
decryption.

This turns out to be trivially breakable:

Capture the ciphertext C
Let N and E be the public modulus and exponent respectively
Let S be a random number > 1 mod N. Doesn't matter what.
Now:
C' = ((S**E mod N) C) mod N
Submit C', which appears totally different from C, to the server, 
recovering P', which appears totally different from P
Now:
          P'
    P = -----  mod N
          S
Oops!

Implement that attack.

Careful about division in cyclic groups.
Remember: you don't simply divide mod N; you multiply by the 
multiplicative inverse mod N. So you'll need a modinv() function.
'''