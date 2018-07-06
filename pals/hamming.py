def hamming(a, b):
    """
    Adds up the difference in the buffers one byte at a time
    """
    return sum([int_format_diff(i, j) for i, j in zip(a, b)])


def int_format_diff(a, b):
    """
    Make binary formatted strings of each int, compare the difference bit by bit
    """
    j = bin(a)[2:].zfill(8)
    k = bin(b)[2:].zfill(8)
    return sum([x != y for x, y in zip(j, k)])


def bit_shift_compare(a, b):
    """
    Thought this might be faster than the string compare -- it is not
    """
    return sum([(a >> i) & 1 != (b >> i) & 1 for i in range(8)])


def edit_distance(data, ks, n):
    """
    Returns hamming distance between chunks of size KS. Does this N times.

    :param data: Data to analyze
    :param ks: Keysize (size of the chunks)
    :param n: Number of times to do this (must be >= 2)
    :return: Floating point score of hamming distance between chunks
    """
    diff = 0
    for i in range(n):
        x = i * ks
        y = x + ks
        a = data[x:y]
        b = data[y:y + ks]
        diff += hamming(a, b)
    return (diff / n) / ks
