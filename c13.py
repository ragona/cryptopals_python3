from Crypto import Random
from pals import utils
import re

random_key = Random.get_random_bytes(16) 

def kv_parse(s):
    fields = s.split('&')
    pairs = [f.split('=') for f in fields]
    return {p[0]:p[1] for p in pairs}

def kv_encode(d):
    pairs = []
    for key, value in d.items():
        pairs.append('{}={}'.format(key, value))
    return "&".join(pairs)

def profile_for(email):
    email = re.sub("[&=?]", "", email)
    return kv_encode({
        "email": email,
        "uid": 10,
        "role": 'user'
    })

#the way that the application treats the cookies it gets
def parse_encrypted_profile(b):
    s = utils.aes_ecb_decrypt(b, random_key).decode('ascii')
    return kv_parse(s.rstrip('\x04'))

#the cookie the attacker gets back (we'd b64 this)
def black_box(user_input):
    return utils.aes_ecb_encrypt(bytes(profile_for(user_input), 'ascii'), random_key)

#we need to remove the padding from the encryption
#which is where the real problem is; we can figure
#out what the ecb 16 byte result for 'admin' plus
#padding, then make sure that the first two params
#('email' and 'uid') are neatly contained within
#two 16 byte blocks, and then just append the admin
#block to that 'real' user. this method will then 
#just strip off the padding at the end, and we have
#an admin user.

#first we jam in a bunch of 16 byte blocks of 'admin'
#plus padding to take us to the end of the block
enc = black_box('A' * 10 + ('admin' + '\x04' * 11) * 10)
dec = parse_encrypted_profile(enc)

print('===== bad ======')
print(len(enc), dec)
blocks = utils.get_blocks(enc, 16)
[print(len(block), block) for block in blocks]

#grab one of the admin blocks
tail = blocks[3] 

print('===== good =====')
enc = black_box('elvtd@foo.com')
dec = parse_encrypted_profile(enc)
print(dec)
blocks = utils.get_blocks(enc, 16)
[print(len(block), block) for block in blocks]

#grab the first two blocks for the user who will get access
head = blocks[0] + blocks[1]

#submit the combined blocks as an encrypted cookie
print('==== combined =====')
print(parse_encrypted_profile(head + tail))

#email=&uid=10&role=
#     ^5           ^12
#email=elvtd@foo.com

'''
ECB cut-and-paste
Write a k=v parsing routine, as if for a structured cookie. 
The routine should take:

foo=bar&baz=qux&zap=zazzle
... and produce:

{
  foo: 'bar',
  baz: 'qux',
  zap: 'zazzle'
}
(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, 
given an email address. You should have something like:

profile_for("foo@bar.com")
... and it should produce:

{
  email: 'foo@bar.com',
  uid: 10,
  role: 'user'
}
... encoded as:

email=foo@bar.com&uid=10&role=user
Your "profile_for" function should not allow encoding 
metacharacters (& and =). Eat them, quote them, whatever you 
want to do, but don't let people set their email address to 
"foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:

Encrypt the encoded user profile under the key; "provide" 
that to the "attacker".

Decrypt the encoded user profile and parse it.

Using only the user input to profile_for() (as an oracle to 
generate "valid" ciphertexts) and the ciphertexts themselves, 
make a role=admin profile.
'''