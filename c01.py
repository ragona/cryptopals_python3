from binascii import unhexlify
from base64 import b64encode


def hex_to_b64(s):
    """
    Converts hex encoded string to base 64 encoded string
    :param s: Hex encoded string
    :return:  Base64 encoded string
    """
    return b64encode(unhexlify(s))


def main():
    a = b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    b = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

    assert hex_to_b64(a) == b


if __name__ == '__main__':
    main()

"""
Convert hex to base64
The string:

49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
Should produce:

SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
So go ahead and make that happen. 
You'll need to use this code for the rest of the exercises.
"""