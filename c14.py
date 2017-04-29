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

# 00000000 0XXXXXXX XXXXXXXX XXXXXXXX

from Crypto import Random
from pals import utils
import base64
import random

rand_key = Random.get_random_bytes(16)
l = 15#random.randrange(24, 150)
prefix = Random.get_random_bytes(l)
unknown = b'this is the good stuff'

def black_box(user_input):
    return utils.aes_ecb_encrypt(prefix + user_input + unknown, rand_key)

# send in no input then single byte  
# and see which block of the return  
# changes; this block contains the 
# edge of the prefix

def prefix_length():
    a = last_prefix_block()
    b = prefix_tail_length(16)

    return a + b

def last_prefix_block():
    a = utils.get_blocks(black_box(b''), 16)
    b = utils.get_blocks(black_box(b'A'), 16)
    for i in range(len(a)):
        if a[i] != b[i]:
            return i * 16
    return -1

#
def prefix_tail_length(blocksize):
    for i in range(blocksize):
        pad = b'A' * (i + blocksize * 2)
        blocks = utils.get_blocks(black_box(pad), 16)
        for j in range(len(blocks) - 1):
            if blocks[j] == blocks[j + 1]:
                return blocksize - i
    raise Exception("sorry pal")

# prefix_edge = last_prefix_block()
# ltp = length_to_pad(16)
# print(ltp)
# print(prefix_edge + ltp)

# print( + l % 16)
# ll = 16

lpb = last_prefix_block()
ptl = prefix_tail_length(16) % 16
print("last_prefix_block {} prefix_tail_len {}".format(lpb, ptl))
print(   utils.ecb_byte_aat(black_box, lpb, ptl)   )

'''
Byte-at-a-time ECB decryption (Harder)

Take your oracle function from #12. Now generate 
a random count of random bytes and prepend this 
string to every plaintext. You are now doing:

AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

Same goal: decrypt the target-bytes.
'''