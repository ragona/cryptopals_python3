'''
The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.
'''

# unhex
# convert to ints
# xor ints against single int in the ascii range
# test the result and see if seems like english

import binascii

s = b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

# https://en.wikipedia.org/wiki/Letter_frequency
freqTable = {" ": 13, "a": 8.16, "b": 1.49, "c": 2.78, "d": 4.25, "e": 12.70, "f": 2.22, "g": 2.01, "h": 6.09, "i": 6.96, "j": 0.15, "k": 0.77, "l": 4.02,
             "m": 2.40, "n": 6.74, "o": 7.50, "p": 1.92, "q": 0.09, "r": 5.98, "s": 6.32, "t": 9.05, "u": 2.75, "v": 0.97, "w": 2.36, "x": 0.15, "y": 1.97, "z": 0.07}

def singleCharXor(s, k):
    return "".join([chr(c ^ k) for c in s])

def scoreEnglishness(s):
    return sum([freqTable[c] if c in freqTable else 0 for c in s])

def getMostEnglishDecryption(s):
    best = ""
    bestScore = 0
    for i in range(255):
        result = singleCharXor(s, i)
        score = scoreEnglishness(result)
        if score > bestScore:
            bestScore = score
            best = result
    return [bestScore, best]

result = getMostEnglishDecryption(binascii.unhexlify(s))

print(result)