#Break repeating-key XOR

import base64

#=====================
# XOR AND SCORING 
#=====================

# https://en.wikipedia.org/wiki/Letter_frequency
freqTable = {" ": 13, "a": 8.16, "b": 1.49, "c": 2.78, "d": 4.25, "e": 12.70, "f": 2.22, "g": 2.01, "h": 6.09, "i": 6.96, "j": 0.15, "k": 0.77, "l": 4.02,
             "m": 2.40, "n": 6.74, "o": 7.50, "p": 1.92, "q": 0.09, "r": 5.98, "s": 6.32, "t": 9.05, "u": 2.75, "v": 0.97, "w": 2.36, "x": 0.15, "y": 1.97, "z": 0.07}

#goes through a buffer (s) and xors it against a single int key (k)
#returns the string representation of it 
def singleCharXor(s, k):
    return "".join([chr(c ^ k) for c in s])

#compares a string to the freq table and gives it a score
def scoreEnglishness(s):
    return sum([freqTable[c] if c in freqTable else 0 for c in s])

#=====================
# HAMMING DISTANCE 
#=====================

#add up the difference in the buffers one byte at a time
def hamming(a, b):
    return sum([int_format_diff(i, j) for i, j in zip(a, b)])

#make binary formatted strings of each int, compare the difference
def int_format_diff(a, b):
    j = bin(a)[2:].zfill(8)
    k = bin(b)[2:].zfill(8)
    return sum([x != y for x, y in zip(j, k)])

#thought this might be faster than the string compare -- it is not
def bit_shift_compare(a, b):
    return sum([(a>>i)&1 != (b>>i)&1 for i in range(8)])

#===============
# EDIT DIST 
#===============

#ks is keysize, n is number of iterations to perform
#return diff averaged over n iterations normalized by ks
def compare_sized_chunks(data, ks, n):
    diff = 0
    for i in range(n):
        x = i * ks
        y = x + ks
        a = data[x : y]
        b = data[y : y + ks]
        diff += hamming(a, b)
    return (diff / n) / ks

#===============
# DECRYPTION 
#===============

def decypher(filename):
    f = open(filename, "rb")
    d = base64.b64decode(f.read())

    #get edit distances for key sizes 2 to 40, return as tuple [keysize, edit distance]
    edit_distances = [[ks, compare_sized_chunks(d, ks, 4)] for ks in range(2, 40)]

    #get top five sorted by edit distance (tuple[1])
    top_5 = sorted(edit_distances, key=lambda x: x[1])[:5]

    #try each of the keysize guesses and score the results
    results = []
    for guess in top_5:
        #guess is a tuple of [keysize, score]
        ks = guess[0] 
        #create ks bytearrays so we can stack our characters and solve them as single char xors
        blocks = [bytearray() for i in range(ks)]
        #jam each byte into one of the arrays
        for i, b in enumerate(d):
            blocks[i%ks].append(b)

        #solve each key block as a single key xor problem
        key = []
        for i, block in enumerate(blocks):
            key_results = [[key, scoreEnglishness(singleCharXor(block, key))] for key in range(1, 255)]
            sorted_keys = sorted(key_results, key=lambda x: x[1])
            #get the best result scored by englishness and add it to the key array
            key.append(sorted_keys[-1][0])

        # rotating decode
        results.append(["".join([chr(b ^ key[i % len(key)]) for i, b in enumerate(d)]), key])

    #examine all results
    bestResult = ""
    bestScore = 0
    for result in results:
        score = scoreEnglishness(result[0])
        if score > bestScore:
            bestResult = result
            bestScore = score

    #print the best result and its key
    print("{}\n=====\nkey: '{}'".format(bestResult[0], "".join([chr(c) for c in bestResult[1]])))

    f.close()


decypher("files/c6.txt")

'''
There's a file here. It's been base64'd after being encrypted with repeating-key XOR.
Decrypt it.

Here's how:

1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:
this is a test
and
wokka wokka!!!
is 37. Make sure your code agrees before you proceed.
2. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
3. The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
4. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
5. Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
6. Solve each block as if it was single-character XOR. You already have code to do this.
7.For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.
This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important.
'''