import binascii
import itertools

#=====================
# FIND ECB 
#=====================

def find_ecb(file, size):
    lines = open(file, 'rb').readlines()
    highest = 0
    ecb_line = None
    for i, line in enumerate(lines[:-1]):
        blocks = [line[i:i+size] for i in range(0, len(line), size)]
        combos = itertools.combinations(blocks, 2)
        score = sum([c[0] == c[1] for c in combos])
        if score > highest:
            highest = score
            ecb_line = line

    #results
    print("==================")
    print(ecb_line)
    print("==================")
    [print(x) for x in sorted([ecb_line[i:i+size] for i in range(0, len(ecb_line), size)])]
    print("==================")

find_ecb("files/c8.txt", 32)

'''
Detect AES in ECB mode
In this file are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic; 
the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
'''