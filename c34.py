from Crypto.Cipher import AES
from Crypto import Random
from pals.utils import modexp, pad 
import random 
import hashlib

g = 2
p = int(('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
         'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
         '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
         '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
         '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
         'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
         'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
         'fffffffffffff'), 16) #just for formatting

class DHClient:

    def __init__(self):
        self.a = random.randint(0, 2<<32)

    #initiates key exchange with a partner. provides p, g, and public key
    #partner will repsond with public key, which is used to set session key
    def connect(self, partner, p, g):
        #generate my public key
        A = modexp(g, self.a, p) 
        #get their public key
        B = partner.accept_connection(p, g, A)
        #set the session key
        self.session_key = modexp(B, self.a, p)

    #responds to key exchange request from partner
    #returns public key, sets session key
    def accept_connection(self, p, g, B):
        #set the session key 
        self.session_key = modexp(B, self.a, p)
        #return my public key
        return modexp(g, self.a, p) 

    def aes_key(self):
        return hashlib.sha1(str(self.session_key).encode()).hexdigest()[:16]

    def encrypt_message(self, message):
        iv = Random.get_random_bytes(16)
        return AES.new(self.aes_key(), AES.MODE_CBC, iv).encrypt(pad(message, 16)) + iv

    def decrypt_message(self, message):
        iv = message[-16:]
        return AES.new(self.aes_key(), AES.MODE_CBC, iv).decrypt(message[:16])

#public keys are swapped out with p 
class MITMDHClient(DHClient):

    def connect(self, partner, p, g):
        partner.accept_connection(p, g, p)
        self.session_key = modexp(p, self.a, p)

    def accept_connection(self, p, g, B):
        return p

#=================
# The normal case
#=================

#create clients
alice = DHClient()
bob = DHClient()

#handshake between alice and bob
alice.connect(bob, p, g)

#encrypt message both parties can read
msg = alice.encrypt_message(b'foo')

print(bob.decrypt_message(msg))
print(alice.decrypt_message(msg))

#=================
# The MITM case
#=================

alice = DHClient()
bob = DHClient()
eve = MITMDHClient()

#alice tries to handshake with bob, but uh oh, she's talking to eve
print('alice to eve')
alice.connect(eve, p, g)

#eve connects with bob 
print('eve to bob')
eve.connect(bob, p, g) 

#alice creates a message
msg = bob.encrypt_message(b'banana')

#everyone can read these messages
print('bob', bob.decrypt_message(msg))
print('eve', eve.decrypt_message(msg))
print('alice', alice.decrypt_message(msg))


'''
Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
Use the code you just worked out to build a protocol and an "echo" bot. You don't 
actually have to do the network part of this if you don't want; just simulate that. 
The protocol is:

A->B
Send "p", "g", "A"
B->A
Send "B"
A->B
Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
B->A
Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
(In other words, derive an AES key from DH with SHA1, use it in both directions, 
and do CBC with random IVs appended or prepended to the message).

Now implement the following MITM attack:
A->M
Send "p", "g", "A"
M->B
Send "p", "g", "p"
B->M
Send "B"
M->A
Send "p"
A->M
Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
M->B
Relay that to B
B->M
Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
M->A
Relay that to A
M should be able to decrypt the messages. "A" and "B" in the 
protocol --- the public keys, over the wire --- have been swapped 
out with "p". Do the DH math on this quickly to see what that does 
to the predictability of the key.

Decrypt the messages from M's vantage point as they go by.

Note that you don't actually have to inject bogus parameters to make this attack work; 
you could just generate Ma, MA, Mb, and MB as valid DH parameters to do a generic MITM 
attack. But do the parameter injection attack; it's going to come up again.
'''