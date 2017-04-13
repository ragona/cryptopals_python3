'''
Fixed XOR
Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:

1c0111001f010100061a024b53535009181c
... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965
... should produce:

746865206b696420646f6e277420706c6179
'''

import binascii

a = '1c0111001f010100061a024b53535009181c'
b = '686974207468652062756c6c277320657965'

def xorHexStrings(a, b):
        unhexedA = binascii.unhexlify(a)
        unhexedB = binascii.unhexlify(b)
        intListA = map(ord, unhexedA)
        intListB = map(ord, unhexedB)
        xoredInts = map(lambda pair: pair[0] ^ pair[1], zip(intListA, intListB))
        joinedStr = "".join(map(chr, xoredInts))
        return binascii.hexlify(joinedStr)

print xorHexStrings(a, b)
