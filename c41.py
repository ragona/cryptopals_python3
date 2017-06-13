from Crypto.Util.number import inverse
from pals.RSA import RSA, int_to_bytes, bytes_to_int
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

def unpadded_recovery_oracle(pub_key, C):
    #setup attack variables
    E = pub_key[0]
    N = pub_key[1] 
    S = 2<<32 % N  
    #create a reversible bignum different from C 
    #the server will decrypt it, and then we can
    #just reverse this operation to get the plain
    nC = (pow(S, E, N) * C) % N
    #send it back to the server
    nP = decypher_blob(nC)
    #reverse it 
    P = (bytes_to_int(nP) // S) % N
    return int_to_bytes(P)

#this happens somewhere else 
blob = generate_blob('555-55-5555')
#we capture this encrypted blob, along with the pub key
C = encrypt_blob(blob)
#we trivially decrypt the blob with the ciphertext and the pub key
recovered = unpadded_recovery_oracle(public, C)

print('original:', blob)
print('recovered:', recovered)

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