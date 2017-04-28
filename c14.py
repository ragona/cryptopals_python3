# trying to figure out how many bytes to prepend  
# to the input before we start doing the normal
# method of going in byte at a time 

# want 10, pad: 5, len 24/32
# 00000000 00YYYYYY YYYPPPPP
# 00000000 00XYYYYY YYYYPPPP
# 00000000 00XXYYYY YYYYYPPP
# 00000000 00XXXYYY YYYYYYPP
# 00000000 00XXXXYY YYYYYYYP
# 00000000 00XXXXXY YYYYYYYY
# 00000000 00XXXXXX YYYYYYYY YPPPPPPP

# want 4, pad: 1, len 16/24
# 0000YYYY YYYYYYYP
# 0000XYYY YYYYYYYY
# 0000XXYY YYYYYYYY YPPPPPPP
# 0000XXXX XXXXXXXX XXXXXXXX
# 0000XXXX XXXXYYYY YYYYYYYP
# 0000XXXX XXXXXXXX YYYYYYYYYYY

# 0000YYYY YYYYYYYP


from Crypto import Random
from pals import utils
import base64
import random

rand_key = Random.get_random_bytes(16)
prefix = Random.get_random_bytes(random.randrange(24, 150))
unknown = b'this is the good stuff'

def black_box(user_input):
    return utils.aes_ecb_encrypt(prefix + user_input + unknown, rand_key)

# send in no input then single byte  
# and see which block of the return  
# changes; this block contains the 
# edge of the suffix   
def last_suffix_block():
    a = utils.get_blocks(black_box(b''), 16)
    b = utils.get_blocks(black_box(b'A'), 16)
    for i in range(len(a)):
        if a[i] != b[i]:
            return i
    return -1

suffix_edge = last_suffix_block()

'''
Byte-at-a-time ECB decryption (Harder)

Take your oracle function from #12. Now generate 
a random count of random bytes and prepend this 
string to every plaintext. You are now doing:

AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

Same goal: decrypt the target-bytes.
'''