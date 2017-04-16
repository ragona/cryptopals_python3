#Break repeating-key XOR

# https://en.wikipedia.org/wiki/Letter_frequency
freqTable = {"a": 8.16, "b": 1.49, "c": 2.78, "d": 4.25, "e": 12.70, "f": 2.22, "g": 2.01, "h": 6.09, "i": 6.96, "j": 0.15, "k": 0.77, "l": 4.02,
             "m": 2.40, "n": 6.74, "o": 7.50, "p": 1.92, "q": 0.09, "r": 5.98, "s": 6.32, "t": 9.05, "u": 2.75, "v": 0.97, "w": 2.36, "x": 0.15, "y": 1.97, "z": 0.07}

def singleCharXor(s, k):
    return "".join([chr(c ^ k) for c in s])

def scoreEnglishness(s):
    return sum([freqTable[c] if c in freqTable else 0 for c in s])

#=====================
# HAMMING DISTANCE 
#=====================

# Write a function to compute the edit distance/Hamming distance between two
# strings. The Hamming distance is just the number of differing bits. 

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

# For each KEYSIZE, take the first KEYSIZE worth of bytes, 
# and the second KEYSIZE  worth of bytes, and find the edit distance 
# between them. Normalize this result by dividing by KEYSIZE.

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

def decypher():
    # Open the file 
    f = open("c6.txt", "rb")
    d = f.read()

    # 1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
    edit_distances = [[ks, compare_sized_chunks(d, ks, 4)] for ks in range(2, 40)]

    # 4. The KEYSIZE with the smallest normalized edit distance is probably the key. 
    # You could proceed perhaps with the smallest 2-3 KEYSIZE values. 
    # Or take 4 KEYSIZE blocks instead of 2 and average the distances.
    top_5 = sorted(edit_distances, key=lambda x: x[1])[:5]
    
    # 5. Now that you probably know the KEYSIZE: 
    # break the ciphertext into blocks of KEYSIZE length.

    # 6. Now transpose the blocks: make a block that is the 
    # first byte of every block, and a block that is the 
    # second byte of every block, and so on.

    #3, 20, 4
    blocks = [bytearray() for i in range(3)]
    for i, b in enumerate(d):
        blocks[i%3].append(b)

    # 7. Solve each block as if it was single-character XOR.
    key = []
    for i, block in enumerate(blocks):
        print("BLOCK {}".format(i))
        # [print(key, scoreEnglishness(singleCharXor(block, key))) for key in range(30, 40)]
        key_results = [[key, scoreEnglishness(singleCharXor(block, key))] for key in range(1, 255)]
        key.append(sorted(key_results, key=lambda x: x[1])[-1:][0])

    print(key)
        
    # 8. For each block, the single-byte XOR key that 
    # produces the best looking histogram is the repeating-key 
    # XOR key byte for that block. Put them together and 
    # you have the key.

    f.close()


decypher()

