import base64
from pals import hamming
from pals import freq_analysis


class KeysizeGuesser:

    class KeysizeGuess:
        def __init__(self, keysize, edit_distance):
            self.keysize = keysize
            self.edit_distance = edit_distance

    def __init__(self, ciphertext, max_keysize=40):
        self.ciphertext = ciphertext
        self.max_keysize = max_keysize
        self.sorted_guesses = []

    def guess_keysize(self):
        edit_distances = [
            KeysizeGuesser.KeysizeGuess(
                keysize, hamming.edit_distance(self.ciphertext, keysize, 4)
            ) for keysize in range(2, self.max_keysize)
        ]

        self.sorted_guesses = sorted(edit_distances, key=lambda x: x.edit_distance)


def main():
    # open the file and decode to get raw bytes
    f = open('files/c6.txt', "rb")
    data = base64.b64decode(f.read())

    # guess the keysize based on hamming distances
    keysize_guesser = KeysizeGuesser(data)
    keysize_guesser.guess_keysize()

    # get top five sorted by edit distance -- the lowest edit distance is not necessarily the right one
    top_5 = keysize_guesser.sorted_guesses[:5]

    # try each of the keysize guesses and score the results
    results = []
    for guess in top_5:
        # create n=keysize bytearrays so we can stack our characters and solve them as single char xors.
        # the property we're taking advantage of here is that if the key is "ICE" (as in the last challenge),
        # the 1st, 4th, 7th characters are all just XOR'd with "I", so with enough English ciphertext we can
        # do standard frequency analysis on those characters against a single key. Note that this needs a fair
        # amount of ciphertext in order to work.
        blocks = [bytearray() for _ in range(guess.keysize)]

        # put each byte into one of the arrays
        for i, b in enumerate(data):
            blocks[i % guess.keysize].append(b)

        # solve each key block as a single key xor problem, then put the key together
        key = []
        for i, block in enumerate(blocks):
            block_guess = freq_analysis.most_english_definition(block)
            key.append(block_guess.key)

        # rotating decode (plus turning the code from ints to chrs)
        combined_plaintext = "".join([chr(c ^ key[i % len(key)]) for i, c in enumerate(data)])
        plaintext_key = "".join(chr(c) for c in key)

        # add these to the list of guesses as a tuple
        results.append((combined_plaintext, plaintext_key))

    # examine results for all keysizes with frequency analysis
    best_result = ""
    best_score = 0
    for result in results:
        score = freq_analysis.english_frequency_score(result[0])
        if score > best_score:
            best_result = result
            best_score = score

    # print the best result and its key
    print(best_result[0])
    print("key:", best_result[1])

    f.close()


if __name__ == '__main__':
    main()

'''
There's a file here. It's been base64'd after being encrypted with repeating-key XOR.
Decrypt it.

Here's how:

1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the 
number of differing bits. The distance between:
this is a test
and
wokka wokka!!!
is 37. Make sure your code agrees before you proceed.
2. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit 
distance between them. Normalize this result by dividing by KEYSIZE.
3. The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the 
smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
4. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
5. Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of 
every block, and so on.
6. Solve each block as if it was single-character XOR. You already have code to do this.
7.For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte 
for that block. Put them together and you have the key.
This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically 
is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it than can actually break 
it, and a similar technique breaks something much more important.
'''