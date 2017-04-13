'''
The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.
'''

# unhex
# convert to ints
# xor ints against single int in the ascii range
# test the result and see if seems like english

import binascii

hex_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

def xorStringAgainstKey(s, k):
        ints = map(ord, s)
        xord = [c ^ k for c in ints]
        return "".join(map(chr, xord))

def scoreEnglishness(s):
        score = 0
        for c in s:
                score += 1 if str.isalpha(c) else -1
        return score

s = binascii.unhexlify(hex_string)
best = ""
bestScore = 0
key = ""
for i in range(255):
        result = xorStringAgainstKey(s, i)
        score = scoreEnglishness(result)
        if score > bestScore:
                bestScore = score
                best = result
                key = chr(i)

print key, bestScore, best
