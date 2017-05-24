from pals.sha1 import Sha1Hash
from binascii import unhexlify 
import struct

#taken from _produce_digest() method in sha1
#see https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction#MD-compliant_padding
def pad_message(message):
    message_byte_length = len(message)
    message += b'\x80'
    message += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)
    message_bit_length = message_byte_length * 8
    message += struct.pack(b'>Q', message_bit_length)
    return message

def mac(data):
    return Sha1Hash().update(b'foo' + data).hexdigest()


s = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
#original hash
good_mac = mac(s)
#reversed state of five 32 bit ints 
state = struct.unpack('>5I', unhexlify(good_mac))
#reset the state of the hash
cloned_sha1 = Sha1Hash()
cloned_sha1.replace_state(state)
#pad with the length of the key (will need to automate) 
inject = b';admin=true'
forged = pad_message(b'AAA' + s)[3:] + inject
#make new mac
bad_mac = cloned_sha1.update(forged).hexdigest()


print(good_mac)
print(bad_mac)
print(mac(s + inject))

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