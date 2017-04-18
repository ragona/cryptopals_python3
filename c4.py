'''
Detect single-character XOR
One of the 60-character strings in this file has been encrypted by single-character XOR.

Find it.
'''

# load the file
# for each line in the file, xor the unhexed string against chars between 0-255
# evaluate the result for "englishness" by scoring with english letter frequency 
# return the "most english" decryption for that line
# if that decryption is more english than the best thing we've seen, declare it the frontrunner
# print the best decryption we've seen

import binascii

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

with open("files/c4.txt", "rb") as f:
    data = f.read()
    lines = data.split(b'\n')
    best = ""
    bestScore = 0
    for line in lines:
        lineResult = getMostEnglishDecryption(binascii.unhexlify(line))
        if lineResult[0] > bestScore:
            bestScore = lineResult[0]
            best = lineResult[1]
    print(best)
