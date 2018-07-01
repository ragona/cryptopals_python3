import binascii


def fixed_xor(a, b):
    """
    Takes two equal-length buffers and produces their byte-by-byte XOR combination
    """
    if len(a) != len(b):
        raise ValueError(f"Expected a and b to be the same length; got {len(a)} vs {len(b)}")

    return bytes([a[i] ^ b[i] for i in range(len(a))])


def main():
    a = binascii.unhexlify(b'1c0111001f010100061a024b53535009181c')
    b = binascii.unhexlify(b'686974207468652062756c6c277320657965')
    x = binascii.hexlify(fixed_xor(a, b))

    assert x == b'746865206b696420646f6e277420706c6179'


if __name__ == '__main__':
    main()


"""
Fixed XOR
Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:

1c0111001f010100061a024b53535009181c
... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965
... should produce:

746865206b696420646f6e277420706c6179
"""