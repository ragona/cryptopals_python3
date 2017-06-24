from Crypto.Util import number
from Crypto import Random
from os import urandom
from hashlib import sha1
from pals.utils import int_to_bytes, bytes_to_int
import re

'''
RFC 2313: https://tools.ietf.org/html/rfc2313
PKCS #1: RSA Encryption
Version 1.5

   ab   hexadecimal octet value  c    exponent
   BT   block type               d    private exponent
   D    data                     e    public exponent
   EB   encryption block         k    length of modulus in
                                        octets
   ED   encrypted data           n    modulus
   M    message                  p, q  prime factors of modulus
   MD   message digest           x    integer encryption block
   MD'  comparative message      y    integer encrypted data
          digest
   PS   padding string           mod n  modulo n
   S    signature                X || Y  concatenation of X, Y
                                 ||X||  length in octets of X

   EB = 00 || BT || PS || 00 || D .

   The block type BT shall be a single octet indicating the structure of
   the encryption block. For this version of the document it shall have
   value 00, 01, or 02. For a private- key operation, the block type
   shall be 00 or 01. For a public-key operation, it shall be 02.

   The padding string PS shall consist of k-3-||D|| octets. For block
   type 00, the octets shall have value 00; for block type 01, they
   shall have value FF; and for block type 02, they shall be
   pseudorandomly generated and nonzero. This makes the length of the
   encryption block EB equal to k.

'''

def pkcs115_hash_pad(M, n, block_type=1):
        D = sha1(M).digest()
        k = n.bit_length() // 8
        if block_type == 1:
            BT = b'\x01' 
            PS = (k - 3 - len(D)) * b'\xFF' 
        elif block_type == 2:
            BT = b'\x02' 
            PS = Random.new().read(k - 3 - len(D)) 
        return b'\x00' + BT + PS + b'\x00' + D 

class RSA:

    def generate_keys(key_size=1024, e=65537):
        #d of 1 indicates that the number didn't inverse 
        #appropriately, so we try again until it works.
        #this doesn't happen (often?) when e is 65537, but
        #does happen often when e is 3. 
        d = 1
        while d == 1:
            #this block ensures that n is the right size
            n = 0
            while n.bit_length() != key_size:
                p = number.getPrime(key_size // 2, urandom)
                q = number.getPrime(key_size // 2, urandom)
                n = p * q
            et = (p-1)*(q-1)
            d = number.inverse(e, et)
        return (e, n), (d, n) #public, private

    def encrypt(m, public_key):
        return pow(bytes_to_int(m), public_key[0], public_key[1]) #e, n

    def decrypt(m, private_key):
        c = pow(m, private_key[0], private_key[1]) #d, n
        return int_to_bytes(c)

    '''
    This is the opposite of a normal operation, we 'decrypt' to 
    generate 'plaintext' bytes that will be later verified using 
    a public key.
    '''
    def generate_signature(message, private_key):
        block = pkcs115_hash_pad(message, private_key[1])
        return RSA.decrypt(bytes_to_int(block), private_key)    

    '''
    Bad implementation of signature verification; it looks for the
    right general pattern, but doesn't check all of the padding. 
    '''
    def verify_signature_vulnerable(signature, message, public_key):
        s = b'\x00' + int_to_bytes(RSA.encrypt(signature, public_key))
        r = re.compile(b'\x00\x01\xFF+?\x00(.{20})', re.DOTALL) #Vulnerable implementation
        g = re.match(r, s)
        if g is None:
            return False
        return g[1] == sha1(message).digest() 

    '''
    Fixes the above vulnerability by enforcing that the pkcs padding 
    exactly matches, instead of just looking for the general pattern
    and testing to see if the sha1 of the message is matched. 
    '''
    def verify_signature(signature, message, public_key, block_type=1):
        #reverse the 'decrypt' done by generate_signature
        plain = b'\x00' + int_to_bytes(RSA.encrypt(signature, public_key))
        #pad user submitted message
        test = pkcs115_hash_pad(message, public_key[1], block_type)
        #verify 
        if plain != test:
            return False
        return True


