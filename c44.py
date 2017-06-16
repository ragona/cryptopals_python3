from pals.DSA import DSA, q
from Crypto.Util.number import inverse

def bti(b):
    return int.from_bytes(b, "big")

def itb(i):
    return i.to_bytes((i.bit_length() + 7) // 8, 'big')

class Message:

    def __init__(self, lines):
        self.msg = Message.parse_line(lines[0])
        self.s = Message.parse_line(lines[1])
        self.r = Message.parse_line(lines[2])
        self.m = Message.parse_line(lines[3])

     #     (m1 - m2)
     # k = --------- mod q
     #     (s1 - s2)
    def compare_msg(self, msg):
        return 0

    @staticmethod
    def parse_line(line):
        return line.split(b': ')[1].replace(b'\n', b'')
        


y = int('2d026f4bf30195ede3a088da85e398ef869611d0f68f07'
        '13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8'
        '5519b1c23cc3ecdc6062650462e3063bd179c2a6581519'
        'f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430'
        'f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3'
        '2971c3de5084cce04a2e147821', 16)

with open('files/c44.txt', 'rb') as f:
    lines = f.readlines()
    messages = []
    for i in range(0, len(lines), 4):
        messages.append(Message(lines[i:i+4]))

for message in messages:
    for m in messages:
        if m is not message:
            k = message.compare_msg(m)
            print(k)
            


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