#Break repeating-key XOR

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
# DECRYPTION 
#===============

def decypher():
    # Open the file 
    f = open("c6.txt", "rb")
    d = f.read()

    # 1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.

    # 2. Write a function to compute the edit distance/Hamming distance between two
    # strings. The Hamming distance is just the number of differing bits. 

    # 3. For each KEYSIZE, take the first KEYSIZE worth of bytes, 
    # and the second KEYSIZE  worth of bytes, and find the edit distance 
    # between them. Normalize this result by dividing by KEYSIZE.

    # 4. The KEYSIZE with the smallest normalized edit distance is probably the key. 
    # You could proceed perhaps with the smallest 2-3 KEYSIZE values. 
    # Or take 4 KEYSIZE blocks instead of 2 and average the distances.

    # 5. Now that you probably know the KEYSIZE: 
    # break the ciphertext into blocks of KEYSIZE length.

    # 6. Now transpose the blocks: make a block that is the 
    # first byte of every block, and a block that is the 
    # second byte of every block, and so on.

    # 7. Solve each block as if it was single-character XOR.

    # 8. For each block, the single-byte XOR key that 
    # produces the best looking histogram is the repeating-key 
    # XOR key byte for that block. Put them together and 
    # you have the key.

    f.close()


print(hamming(b"this is a test", b"wokka wokka!!!"))
decypher()

