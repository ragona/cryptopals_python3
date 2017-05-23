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
    return utils.ctr(prefix+user_input+suffix, rand_key, nonce)

def parse(cookie):
    return utils.ctr(cookie, rand_key, nonce)

cookie = black_box(b'foooXadminXtrueX') #36, 42, 47 are the XXX characters
# cookie = flip_bit(cookie, 36, b';')
# cookie = flip_bit(cookie, 42, b'=')
# cookie = flip_bit(cookie, 47, b';')
print(cookie)
print(parse(cookie))


'''
CTR bitflipping
There are people in the world that believe that CTR resists bit flipping 
attacks of the kind to which CBC mode is susceptible.

Re-implement the CBC bitflipping exercise from earlier to use CTR mode 
instead of CBC mode. Inject an "admin=true" token.
'''