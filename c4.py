'''
Detect single-character XOR
One of the 60-character strings in this file has been encrypted by single-character XOR.

Find it.
'''

# load the file
# for each line in the file, xor the unhexed string against chars between 0-255
# evaluate the result for "englishness" by scoring with english letter frequency 
# return the "most english" decryption for that line
# if that decryption is more english than the best thing we've seen, declare it the frontrunner
# print the best decryption we've seen

import binascii
from pals import utils

with open("files/c4.txt", "rb") as f:
    data = f.read()
    lines = data.split(b'\n')
    best = ""
    bestScore = 0
    for line in lines:
        lineResult = utils.getMostEnglishDecryption(binascii.unhexlify(line))
        if lineResult[0] > bestScore:
            bestScore = lineResult[0]
            best = lineResult[1]
    print(best)
