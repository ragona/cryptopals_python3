from binascii import unhexlify
from itertools import combinations


def detect_ecb(ciphertext):
    # split ciphertext into 16 byte blocks
    blocks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]
    # find all the pair combinations of the blocks
    combos = combinations(blocks, 2)
    # if any of the pairs are identical we suspect ecb
    for combo in combos:
        if combo[0] == combo[1]:
            return True
    return False


def main():
    with open('files/c8.txt', 'rb') as f:
        for line in f.readlines():
            ciphertext = unhexlify(line.strip())
            is_ecb = detect_ecb(ciphertext)
            if is_ecb:
                print(line)


if __name__ == '__main__':
    main()

'''
Detect AES in ECB mode
In this file are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic; 
the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
'''