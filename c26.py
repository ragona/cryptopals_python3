from pals import utils
from Crypto import Random

rand_key = Random.get_random_bytes(16)
nonce = Random.get_random_bytes(8)
prefix = b'comment1=cooking%20MCs;userdata='  
suffix = b';comment2=%20like%20a%20pound%20of%20bacon'

#setup
def black_box(user_input):
    user_input = user_input.replace(b'=', b'')
    user_input = user_input.replace(b';', b'')
    return parse(prefix+user_input+suffix)

def parse(cookie):
    return utils.ctr(cookie, rand_key, nonce)

#1 pass in zero bytes so we just get the 'key' (encrypted nonce+ctr) back
cookie = bytearray(black_box(b'fooba\x00admin\x00true')) #37, #43 are the XXX characters
#2 swap out the special bytes with what will xor to our target bytes
cookie[37] ^= ord(';')
cookie[43] ^= ord('=')
#3 send it back in to be turned into plaintext
cookie = parse(cookie)
#4 check admin token
print("admin:", b"admin=true" in cookie)
print("cookie:", cookie)

'''
CTR bitflipping
There are people in the world that believe that CTR resists bit flipping 
attacks of the kind to which CBC mode is susceptible.

Re-implement the CBC bitflipping exercise from earlier to use CTR mode 
instead of CBC mode. Inject an "admin=true" token.
'''