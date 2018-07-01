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

from binascii import unhexlify
from pals.freq_analysis import most_english_definition

with open("files/c4.txt", "rb") as f:
    data = f.read()
    lines = data.split(b'\n')
    most_english = ""
    best_score = 0
    for line in lines:
        line_result = most_english_definition(unhexlify(line))
        if line_result[0] > best_score:
            best_score = line_result[0]
            most_english = line_result[1]
    print(most_english)
