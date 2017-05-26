from pals.md4 import MD4
from pals import utils
from binascii import unhexlify 
import struct

#============
# server 
#============

def mac(data):
    return MD4(b'foobanana' + data).hexdigest()

def validate(msg, foo):
    return mac(msg) == foo

#============
# attacker 
#============

def md4_ext(msg, good_mac, inject, key_len):
    #the 'unwound' state of the md4 algorithm
    state = struct.unpack('<4I', unhexlify(good_mac))
    #pad with the length of the key (will need to automate) 
    forged_message = utils.md4_pad(b'A' * key_len + msg)[key_len:] + inject
    #make new mac
    forged_mac = MD4(inject, (key_len + len(forged_message)), state[0], state[1], state[2], state[3]).hexdigest()
    return forged_message, forged_mac
    
#our setup 
msg = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
inject = b';admin=true'
good_mac = mac(msg)

# our attack; guess at initial key prefix sizes
for i in range(100):
    #generate forged mac + msg
    bad_msg, bad_mac = md4_ext(msg, good_mac, inject, i)
    #submit to server, see if it accepts it 
    if validate(bad_msg, bad_mac):
        print('forged message, key len is', i)
        break


'''
Break an MD4 keyed MAC using length extension
Second verse, same as the first, but use MD4 instead of SHA-1. Having done this 
attack once against SHA-1, the MD4 variant should take much less time; mostly 
just the time you'll spend Googling for an implementation of MD4.

You're thinking, why did we bother with this?
Blame Stripe. In their second CTF game, the second-to-last challenge involved 
breaking an H(k, m) MAC with SHA1. Which meant that SHA1 code was floating all 
over the Internet. MD4 code, not so much.
'''