from Crypto import Random
from base64 import b64decode
from pals import utils

nonce = Random.get_random_bytes(8)

def decypher(d, ks):
    results = []
    #create ks bytearrays so we can stack our characters and solve them as single char xors
    blocks = [bytearray() for i in range(ks)]
    #jam each byte into one of the arrays
    for i, b in enumerate(d):
        blocks[i%ks].append(b)

    #solve each key block as a single key xor problem
    key = []
    for i, block in enumerate(blocks):
        key_results = [[key, utils.scoreEnglishness(utils.singleCharXor(block, key))] for key in range(1, 255)]
        sorted_keys = sorted(key_results, key=lambda x: x[1])
        #get the best result scored by englishness and add it to the key array
        key.append(sorted_keys[-1][0])

    # rotating decode
    result = ["".join([chr(b ^ key[i % len(key)]) for i, b in enumerate(d)]), key]

    #print the best result and its key
    print("{}\n=====\nkey: '{}'".format(result[0], "".join([chr(c) for c in result[1]])))

#this works because each block is XORd against the same ciphertext, since the ciphertext
#is a fixed nonce plus a consistent counter. It's basically a big long XOR key that gets 
#repeated for each line. This allows you to concatenate the first N bytes of each cipher 
#into one long block, and solve the whole thing as if it's a repeating key XOR. It does 
#mean that you only get the first N bytes of the ciphertext though, where N is the length
#of the shortest cipher. 
with open('files/c20.txt', 'rb') as f:
    lines = f.readlines()
    concat = bytes()
    for line in lines:
        ciphertext = utils.ctr(bytes(b64decode(line)), b'YELLOW SUBMARINE', nonce)
        concat += ciphertext[:53]

    decypher(concat, 53)



'''
Break fixed-nonce CTR statistically
In this file find a similar set of Base64'd plaintext. Do with them exactly 
what you did with the first, but solve the problem differently.

Instead of making spot guesses at to known plaintext, treat the collection of 
ciphertexts the same way you would repeating-key XOR.

Obviously, CTR encryption appears different from repeated-key XOR, but with a 
fixed nonce they are effectively the same thing.

To exploit this: take your collection of ciphertexts and truncate them to a 
common length (the length of the smallest ciphertext will work).

Solve the resulting concatenation of ciphertexts as if for repeating- key XOR, 
with a key size of the length of the ciphertext you XOR'd.
'''