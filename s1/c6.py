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

    # Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
    # For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE 
    # worth of bytes, and find the edit distance between them. 
    # Normalize this result by dividing by KEYSIZE.
    f.close()


print(hamming(b"this is a test", b"wokka wokka!!!"))
decypher()

