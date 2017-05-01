from Crypto.Cipher import AES
from Crypto import Random
import itertools

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


#================
# CRYPTO
#================

def aes_ecb_encrypt(data, key):
    data = pad(data, (len(data) // 16 + 1) * 16)
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(data)

def aes_ecb_decrypt(data, key):
    return AES.new(key, AES.MODE_ECB).decrypt(data)

def aes_cbc_encrypt(data, key, iv):
    cipher = AES.new(key, AES.MODE_ECB)
    block_size = len(iv)
    results = bytes()
    ciphertext = iv
    for i in range(0, len(data), block_size):
        plaintext = pad(data[i : i + block_size], block_size)
        xord = bytes([plaintext[i] ^ ciphertext[i] for i in range(block_size)]) 
        ciphertext = cipher.encrypt(xord)
        results += ciphertext
    return results

def aes_cbc_decrypt(data, key, iv):
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)

#================
# DETECTION
#================

#if any N bytes are the same it's probably ecb 
#with repeating data
def detect_ecb(data, size=16):
    blocks = [data[i:i+size] for i in range(0, len(data), size)]
    combos = itertools.combinations(blocks, 2)
    score = sum([c[0] == c[1] for c in combos])
    return score > 0 

#================
# PADDING
#================

#pkcs7
def pad(data, size):
    pad_size = size - len(data) % size
    return data + bytes([pad_size]) * pad_size

def unpad(data):
    return data[:-data[-1]]

def pad_string(s, size):
    return pad(bytes(s, 'ascii'), size).decode('ascii')

def unpad_string(s):
    return unpad(bytes(s, 'ascii')).decode('ascii')

#================
# GET BLOCKS
#================

def get_blocks(data, size):
    return [data[i:i+size] for i in range(0, len(data), size)]

#================
# SOLVERS
#================

#send in additional padding bytes until we cause the 
#function (f) to kick us out another block, and then just
#subtract the length of the initial empty result from the 
#new length that we just got
def get_block_size(f):
    start = f(b'')
    i = 1
    while(True):
        result = f(b'A' * i)
        if len(result) != len(start):
            return len(result) - len(start)
        i += 1

#ecb byte at a time 
#f should be a function that takes a byte string  
#and returns an ecb encrypted byte string
def ecb_byte_aat(f):
    #get blocksize first
    blocksize = get_block_size(f)    

    #solve the prefix (if any)
    #we need overall length and the length of the tail
    #prefix_len will be multiple of blocksize, tail_len
    #will be the number of bytes needed to pad the prefix
    #so that we can send in our input below cleanly at the
    #start of a block
    def solve_prefix():
        for i in range(blocksize):
            pad = b'A' * (i + blocksize * 2)
            blocks = get_blocks(f(pad), 16)
            for j in range(len(blocks) - 1):
                if blocks[j] == blocks[j + 1]:
                    return(j * blocksize, i)
        raise Exception("sorry pal")

    prefix_len, tail_len = solve_prefix()

    #we're gonna read the unknown portion by eating 
    #into it one byte at a time by sending in known
    #input plus sized padding such that we can  
    #randomize the very last byte of input 
    solved = b''
    pre = b'A' * tail_len #number of bytes to pad out the prefix block
    pad = b'A' * blocksize
    while True:
        #pad is the empty bytes at the front
        pad = b'A' * ((blocksize - 1 - (len(solved) % blocksize)))
        #overall size, must be will be a multiple of blocksize
        #includes the one byte that we're randomizing, as well
        #as the total length of the prefix bytes 
        size = prefix_len + len(pad) + len(solved) + 1 
        results = {}
        #send (pre + pad + solved + char) into the box, store 
        #the first 'size' bytes in our results dict keyed
        #to the single byte that we used to get the result
        for j in range(0,255):
            test = f(pre + pad + solved + bytes([j])) 
            results[test[0:size]] = bytes([j])
        #send JUST the pad into the black box but test 
        #the same number of bytes off the front of the
        #result against the results table and see if 
        #we have the a matching result in our dict 
        pad_only = f(pre + pad)
        chunk = pad_only[0:size]
        if chunk in results:
            solved += results[chunk]
        else:
            break

    return solved

