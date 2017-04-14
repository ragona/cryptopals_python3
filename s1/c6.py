#Break repeating-key XOR

#=====================
# HAMMING DISTANCE 
#=====================

def hamming(a, b):
    diff = 0
    for i in range(len(a)):
        diff += char_bit_diff(a[i], b[i])
    return diff

# just formats into 8 digit binary format 
# then compares the strings to find the difference
# i.e. "00000001" vs "10000000" would be a diff of 2
# tried a couple things here; this didn't seem like 
# it'd be that fast, but it was somewhat faster than 
# the other option I tried
def char_bit_diff(a, b):
    diff = 0
    sA = format(ord(a), "08b")
    sB = format(ord(b), "08b")
    for i in range(8):
        if sA[i] != sB[i]:
            diff +=1
    return diff

#===============
# DECRYPTION 
#===============

def decypher():
    # Open the file 
    f = open("c6.txt", "r")
    d = f.read()

    # Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
    # For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE 
    # worth of bytes, and find the edit distance between them. 
    # Normalize this result by dividing by KEYSIZE.
    f.close()


# print hamming("this is a test", "wokka wokka!!!")
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
