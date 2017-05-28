import hashlib
from pals.utils import modexp, pad
from Crypto import Random
from Crypto.Random import random
from Crypto.Cipher import AES 

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

#futzing with the g value
class MITM_G_DHClient(DHClient):

    def __init__(self, g_override):
        self.g_override = g_override
        super(MITM_G_DHClient, self).__init__()

    def connect(self, partner, p, g):
        A = modexp(self.g_override, self.a, p) 
        B = partner.accept_connection(p, self.g_override, A)
        self.session_key = modexp(B, self.a, p)

    def accept_connection(self, p, g, B):
        self.session_key = modexp(B, self.a, p)
        return modexp(self.g_override, self.a, p) 