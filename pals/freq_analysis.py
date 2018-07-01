# https://en.wikipedia.org/wiki/Letter_frequency
english_frequency = {" ": 13, "a": 8.16, "b": 1.49, "c": 2.78, "d": 4.25, "e": 12.70, "f": 2.22, "g": 2.01, "h": 6.09,
                     "i": 6.96, "j": 0.15, "k": 0.77, "l": 4.02, "m": 2.40, "n": 6.74, "o": 7.50, "p": 1.92, "q": 0.09,
                     "r": 5.98, "s": 6.32, "t": 9.05, "u": 2.75, "v": 0.97, "w": 2.36, "x": 0.15, "y": 1.97, "z": 0.07}


def single_character_xor(s, k):
    """
    XORs all characters in s against k
    """
    return "".join([chr(c ^ k) for c in s])


def english_frequency_score(s):
    """
    Floating point score of all characters in s, scored against english frequency score table
    """
    return sum([english_frequency[c] if c in english_frequency else 0 for c in s])


def most_english_definition(s):
    """
    Tries all 255 options with the single key XOR method, and scores with the english frequency table.
    Returns a tuple of the highest score and the corresponding text.
    """
    most_english = ""
    highest_score = 0
    for i in range(255):
        result = single_character_xor(s, i)
        score = english_frequency_score(result)
        if score > highest_score:
            highest_score = score
            most_english = result
    return highest_score, most_english
