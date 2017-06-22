from pals.RSA import RSA
from pals.utils import cbrt, bytes_to_int, int_to_bytes
from hashlib import sha1

def fake_signature(message, key_size):
    hsh = sha1(message).digest()
    zero_padding = (key_size // 8 - 4 - len(hsh)) * b'\x00'
    block = b'\x00\x01\xFF\x00' + hsh + zero_padding
    num = cbrt(bytes_to_int(block))
    return int_to_bytes(num)

msg = b'hi mom'
pub, pri = RSA.generate_keys(1024, 3)
real_sig = RSA.generate_signature(msg, pri)
fake_sig = fake_signature(msg, 1024)

print(RSA.verify_signature(real_sig, msg, pub))
print(RSA.verify_signature(fake_sig, msg, pub))

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

Note: Hal Finney writeup here: 
https://www.ietf.org/mail-archive/web/openpgp/current/msg00999.html
'''