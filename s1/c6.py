#Break repeating-key XOR

#=====================
# HAMMING DISTANCE 
#=====================


def hamming(a, b):
    return sum([int_diff(i, j) for i, j in zip(a, b)])

def int_diff(a, b):
    j = bin(a)[2:].zfill(8)
    k = bin(b)[2:].zfill(8)
    return sum([x != y for x, y in zip(j, k)])

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

#=================
# Note code below
#=================

# rejected (but functioning) option for comparing
# binary diff between numbers 
# def bitCompare(a, b):
#     diff = 0
#     nth = lambda x, n: (x>>n)&1
#     for i in range(8):
#         if nth(a, i) != nth(b, i):
#             diff += 1
#     return diff        

