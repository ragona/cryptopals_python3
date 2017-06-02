'''
Going procedural for this one for brevity and clarity. 
For the more reasonably architected examples see c36/37.

To brute force recover a password in a reasonable amount of time
you need the client hmac and the salt. From there you can start 
all the way back at generating the server's x and v values, where
x is H(salt, dictionary_password_guess). I initially spent a while
staring at this and seeing if I could send interesting B, u, salt 
variables and unwind the algorithm somehow, but I think the approach
with the best big O time is to just brute force it starting from
the beginning until you manage to find something that matches the 
client hmac. Note that this only relates to a MITM situation; if 
you had a leaked password database, you'd only have to do the first
calculation of x and v, and if you got a v that matched the stored 
verifier you'd have the password, and this would be a bit faster
than the MITM version. 

Note: Not uploading a 
'''

import hashlib
import tqdm
from pals.srp import H, hash, hmac_sha256
from Crypto.Random import random

#constants
g = 2
k = 3
n = int(('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
         'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
         '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
         '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
         '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
         'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
         'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
         'fffffffffffff'), 16) #just for formatting

#helper
rand = lambda size: random.randint(0, 2<<size)

#shared info
password = 'affliction' #near the beginning of dictionary

#server 
salt = rand(32)
x = H(salt, password)
v = pow(g, x, n)

#client to server
a = rand(32)
A = pow(g, a, n)

#server to client
b = rand(32)
B = pow(g, b, n)
u = rand(128)

#client
x = H(salt, password)
S = pow(B, (a + u * x), n) 
cK = hash(str(S))
cHK = hmac_sha256(salt, cK)

#server
S = pow((A * pow(v, u, n)), b, n)
sK = hash(str(S))
sHK = hmac_sha256(salt, sK)

#verify
print(sHK == cHK)

#start here for the brute force; if you can mitm and act as the 
#server so you have all variables necessary to generate the server
#side S, starting from x and v, then you can just test dictionary
#passwords and catch easy passwords by testing against the hmac
with open('/usr/share/cracklib/cracklib-small') as f:
    i = 0
    for line in tqdm.tqdm(f, total=54763):
        x = H(salt, line.strip())
        v = pow(g, x, n)
        S = pow((A * pow(v, u, n)), b, n)
        K = hash(str(S))
        hK = hmac_sha256(salt, K)
        if hK == cHK:
            print("*****************")
            print("password:", line.strip())
            print("*****************")
            break


'''
Offline dictionary attack on simplified SRP
S
x = SHA256(salt|password)
    v = g**x % n
C->S
I, A = g**a % n
S->C
salt, B = g**b % n, u = 128 bit random number
C
x = SHA256(salt|password)
    S = B**(a + ux) % n
    K = SHA256(S)
S
S = (A * v ** u)**b % n
    K = SHA256(S)
C->S
Send HMAC-SHA256(K, salt)
S->C
Send "OK" if HMAC-SHA256(K, salt) validates
Note that in this protocol, the server's "B" 
parameter doesn't depend on the password (it's 
just a Diffie Hellman public key).

Make sure the protocol works given a valid password.

Now, run the protocol as a MITM attacker: pose as the 
server and use arbitrary values for b, B, u, and salt.

Crack the password from A's HMAC-SHA256(K, salt).
'''