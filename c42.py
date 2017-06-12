from pals.RSA import RSA
import hashlib, base64, binascii 

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

def pkcs115_hash_pad(M, n):
    D = hashlib.sha1(M).digest()
    k = n.bit_length() // 8
    BT = b'\x01' 
    PS = (k - 3 - len(D)) * b'\xFF' 
    return b'\x00' + BT + PS + b'\x00' + D 

msg = b'hi mom'
pub, pri = RSA.generate_keys(1024, 3)

x = pkcs115_hash_pad(msg, pub[1])

print(x)
'''
Bleichenbacher's e=3 RSA Attack
Crypto-tourism informational placard.
This attack broke Firefox's TLS certificate validation several years 
ago. You could write a Python script to fake an RSA signature for any 
certificate. We find new instances of it every other year or so.

RSA with an encrypting exponent of 3 is popular, because it makes the 
RSA math faster.

With e=3 RSA, encryption is just cubing a number mod the public 
encryption modulus:

 c = m ** 3 % n
e=3 is secure as long as we can make assumptions about the message blocks 
we're encrypting. The worry with low-exponent RSA is that the message blocks 
we process won't be large enough to wrap the modulus after being cubed. The 
block 00:02 (imagine sufficient zero-padding) can be "encrypted" in e=3 RSA; 
it is simply 00:08.

When RSA is used to sign, rather than encrypt, the operations are reversed; 
the verifier "decrypts" the message by cubing it. This produces a "plaintext" 
which the verifier checks for validity.

When you use RSA to sign a message, you supply it a block input that contains 
a message digest. The PKCS1.5 standard formats that block as:

00h 01h ffh ffh ... ffh ffh 00h ASN.1 GOOP HASH
As intended, the ffh bytes in that block expand to fill the whole block, 
producing a "right-justified" hash (the last byte of the hash is the last 
byte of the message).

There was, 7 years ago, a common implementation flaw with RSA verifiers: 
they'd verify signatures by "decrypting" them (cubing them modulo the public 
exponent) and then "parsing" them by looking for 00h 01h ... ffh 00h ASN.1 HASH.

This is a bug because it implies the verifier isn't checking all the padding. 
If you don't check the padding, you leave open the possibility that instead 
of hundreds of ffh bytes, you have only a few, which if you think about it 
means there could be squizzilions of possible numbers that could produce a 
valid-looking signature.

How to find such a block? Find a number that when cubed (a) doesn't wrap the 
modulus (thus bypassing the key entirely) and (b) produces a block that 
starts "00h 01h ffh ... 00h ASN.1 HASH".

There are two ways to approach this problem:

You can work from Hal Finney's writeup, available on Google, of how 
Bleichenbacher explained the math "so that you can do it by hand with a pencil".
You can implement an integer cube root in your language, format the message 
block you want to forge, leaving sufficient trailing zeros at the end to fill 
with garbage, then take the cube-root of that block.
Forge a 1024-bit RSA signature for the string "hi mom". Make sure your 
implementation actually accepts the signature!
'''