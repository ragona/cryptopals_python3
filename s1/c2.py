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

#unhexlify the strings, convert each char to an int, xor the ints
#convert the resulting int back to a char, join it into a string
#return the hexlified string
def xorHexStrings(a, b):
        if len(a) != len(b):
                raise Exception("buffers are not of equal length")
        xorChars = lambda pair: ord(pair[0]) ^ ord(pair[1])
        xored = map(xorChars, zip(binascii.unhexlify(a), binascii.unhexlify(b)))
        return binascii.hexlify("".join(map(chr, xored)))

print xorHexStrings(a, b)
