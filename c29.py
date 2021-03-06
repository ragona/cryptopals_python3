'''
Alright, here is my understanding of what is going on here. 
SHA-1 state can be reversed, which allows you to pick back up
hashing content where the algorithm left off. This works because 
the sha-1 hash is just a 160 bit number, so if you split
it into five 32 bit numbers you can use that state to append 
data to the hash. By padding the bad message, you ensure that 
when the MAC is generated by the server, it will advance its state
at the end of the 'real' message and then cleanly move on to 
the appended suffix. 

If the MAC is constructed by just concatenating SECRET + DATA 
then an attacker can create two things; a message with 1) padding out
to the end of the block and 2) bad data appended to the end
of the message. Second, the attacker will submit a MAC that 
will match the MAC produced by the SECRET + DATA on the server
side, so the message will appear to be valid. This is all 
solved by using a hashed MAC (HMAC). 
'''

from pals.sha1 import sha1
from pals import utils
from binascii import unhexlify 
import struct

#============
# server 
#============

def mac(data):
    return sha1(b'banana' + data)

def validate(msg, foo):
    return mac(msg) == foo

#============
# attacker 
#============

def sha1_ext(msg, good_mac, inject, key_len):
    #the 'unwound' state of the sha1 algorithm
    state = struct.unpack('>5I', unhexlify(good_mac))
    #pad with the length of the key (will need to automate) 
    forged_message = utils.sha1_pad((b'A' * key_len) + msg)[key_len:] + inject
    #make new mac
    forged_mac = sha1(inject, (key_len + len(forged_message)) * 8, state[0], state[1], state[2], state[3], state[4])
    return forged_message, forged_mac
    
#our setup 
msg = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
inject = b';admin=true'
good_mac = mac(msg)

#our attack; guess at initial key prefix sizes
for i in range(100):
    #generate forged mac + msg
    bad_msg, bad_mac = sha1_ext(msg, good_mac, inject, i)
    #submit to server, see if it accepts it 
    if validate(bad_msg, bad_mac):
        print('forged message, key len is', i)
        break

'''
Break a SHA-1 keyed MAC using length extension
Secret-prefix SHA-1 MACs are trivially breakable.

The attack on secret-prefix SHA1 relies on the fact that you can take the ouput of 
SHA-1 and use it as a new starting point for SHA-1, thus taking an arbitrary SHA-1 
hash and "feeding it more data".

Since the key precedes the data in secret-prefix, any additional data you feed the 
SHA-1 hash in this fashion will appear to have been hashed with the secret key.

To carry out the attack, you'll need to account for the fact that SHA-1 is "padded" 
with the bit-length of the message; your forged message will need to include that 
padding. We call this "glue padding". The final message you actually forge will be:

SHA1(key || original-message || glue-padding || new-message)
(where the final padding on the whole constructed message is implied)

Note that to generate the glue padding, you'll need to know the original bit length 
of the message; the message itself is known to the attacker, but the secret key isn't,
so you'll need to guess at it.

This sounds more complicated than it is in practice.

To implement the attack, first write the function that computes the MD padding of an 
arbitrary message and verify that you're generating the same padding that your SHA-1 
implementation is using. This should take you 5-10 minutes.

Now, take the SHA-1 secret-prefix MAC of the message you want to forge --- this is just a 
SHA-1 hash --- and break it into 32 bit SHA-1 registers (SHA-1 calls them "a", "b", "c", &c).

Modify your SHA-1 implementation so that callers can pass in new values for 
"a", "b", "c" &c (they normally start at magic numbers). With the registers "fixated", 
hash the additional data you want to forge.

Using this attack, generate a secret-prefix MAC under a secret key (choose a random word 
from /usr/share/dict/words or something) of the string:

"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
Forge a variant of this message that ends with ";admin=true".

This is a very useful attack.
For instance: Thai Duong and Juliano Rizzo, who got to this attack before we did, used it 
to break the Flickr API.
'''
