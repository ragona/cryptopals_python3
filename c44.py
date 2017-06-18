'''
moral of the story: if you have multiple public signatures
that contain the same 'r' value in the (r, s) pair, then 
there was a repeated nonce ('k') value. As we saw in c43,
with a known nonce you can recover the private key ('x')
'''

from hashlib import sha1
from c43 import x_from_nonce
from pals.DSA import DSA, q
from itertools import combinations
from Crypto.Util.number import inverse


def parse_line(line):
    return line.split(b': ')[1].replace(b'\n', b'')

class Message:

    def __init__(self, lines):
        self.msg = parse_line(lines[0])
        self.s = int(parse_line(lines[1]))
        self.r = int(parse_line(lines[2]))
        self.m = int(parse_line(lines[3]), 16)


def parse_messages():
    with open('files/c44.txt', 'rb') as f:
        lines = f.readlines()
        messages = []
        for i in range(0, len(lines), 4):
            messages.append(Message(lines[i:i+4]))
    return messages

#     (m1 - m2)
# k = --------- mod q
#     (s1 - s2)
def recover_repeated_nonce(msg1, msg2, q):
    m = (msg1.m - msg2.m) % q
    s = (msg1.s - msg2.s) % q
    i = inverse(s, q)
    k = (m * i) % q
    return k

#get default p, q, g params
p,q,g,y = DSA.generate_user_key_pair()[0]
y = int('2d026f4bf30195ede3a088da85e398ef869611d0f68f07'
        '13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8'
        '5519b1c23cc3ecdc6062650462e3063bd179c2a6581519'
        'f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430'
        'f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3'
        '2971c3de5084cce04a2e147821', 16)
want = 'ca8f6f7c66fa362d40760d135b763eb8527d3d52'

#k should be unique per message. if it is not, then 'r' 
#in the signature (r, s) will be repeated, since r is just
#pow(g, k, p) % q -- and g, p, q do not change per msg
def main():
    pairs = combinations(parse_messages(), 2)
    for m1, m2 in pairs:
        if m1.r == m2.r:
            k = recover_repeated_nonce(m1, m2, q)
            x = x_from_nonce(m1.msg, (m1.r, m1.s), (p,q,g,y), k)
            hsh = sha1(hex(x)[2:].encode('ascii')).hexdigest()
            assert hsh == want

    print('success')

if __name__ == '__main__':
    main()        


'''
DSA nonce recovery from repeated nonce
Cryptanalytic MVP award.
This attack (in an elliptic curve group) broke the PS3. 
It is a great, great attack.

In this file find a collection of DSA-signed messages. 
(NB: each msg has a trailing space.)

These were signed under the following pubkey:

y = 2d026f4bf30195ede3a088da85e398ef869611d0f68f07
    13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8
    5519b1c23cc3ecdc6062650462e3063bd179c2a6581519
    f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430
    f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3
    2971c3de5084cce04a2e147821
(using the same domain parameters as the previous exercise)

It should not be hard to find the messages for which we have 
accidentally used a repeated "k". Given a pair of such messages, 
you can discover the "k" we used with the following formula:

         (m1 - m2)
     k = --------- mod q
         (s1 - s2)
9th Grade Math: Study It!
If you want to demystify this, work out that equation from the 
original DSA equations.

Basic cyclic group math operations want to screw you
Remember all this math is mod q; s2 may be larger than s1, for 
instance, which isn't a problem if you're doing the subtraction 
mod q. If you're like me, you'll definitely lose an hour to forgetting 
a paren or a mod q. (And don't forget that modular inverse function!)
What's my private key? Its SHA-1 (from hex) is:

   ca8f6f7c66fa362d40760d135b763eb8527d3d52
'''