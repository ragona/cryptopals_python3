from binascii import unhexlify
from pals.freq_analysis import most_english_definition


def main():
    # open the challenge file
    with open("files/c4.txt", "rb") as f:
        most_english = ""
        best_score = 0
        for line in f.readlines():
            # try each single character (0-255) key on this line, get the result that
            # best fits the english frequency scoring table.
            line_result = most_english_definition(
                unhexlify(line.strip())
            )
            # if this is the highest score, store it
            if line_result.score > best_score:
                best_score = line_result.score
                most_english = line_result.plaintext

        # output our best result
        print(most_english)


if __name__ == '__main__':
    main()


"""
Detect single-character XOR
One of the 60-character strings in this file has been encrypted by single-character XOR.

Find it.
"""
