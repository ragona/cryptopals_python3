import os

from c52 import merkle_damgard


DEFAULT_IV = b'\x00' * 16
SIZE = 3


class Collision:
    def __init__(self, m0, m1, h_in, h_tmp, result):
        self.m0 = m0
        self.m1 = m1
        self.h_in = h_in
        self.h_tmp = h_tmp
        self.result = result

    def __str__(self):
        return f"Collision(m0={self.m0}, m1={self.m1}, h_in={self.h_in}, h_tmp={self.h_tmp}, result={self.result})"

    def __repr__(self):
        return self.__str__()


def F(iv, m):
    return merkle_damgard(message=m, iv=iv, size=SIZE)


def find_collision(num_blocks, iv):
    """
    ALGORITHM: FindCollision(α, h_in)
    Find a collision pair with lengths 1 and blocks, starting from h_in.

    Variables:
        1. α = desired length of second message. (num_blocks)
        2. A, B = lists of intermediate hash values.
        3. q = a fixed “dummy” message used for getting the desired length.
        4. h_in = the input hash value for the collision.  (iv)
        5. h_tmp = intermediate hash value used in the attack.
        6. M(i) = the ith distinct message block used in the attack.
        7. n = width of hash function chaining value and output in bits.

    Work: α − 1 + 2n/2+1 compression function calls
    """
    q = DEFAULT_IV
    h_in = iv

    """
    1. Compute the starting hash for the α-block message by processing α − 1
    dummy message blocks:
        – h_tmp = h_in.
        – For i = 0 to α − 2:
            • h_tmp = F(h_tmp, q)
    
    We're priming the chaining value so that we can focus on the last block in step 2. (Note that this loop is just a 
    Merkle-Damgard construction; we can use our existing F with a prefix of appropriate length.) 
    """
    prefix = q * (num_blocks - 2)
    h_tmp = F(h_in, prefix)

    """
    2. Build lists A and B as follows:
        – for i = 0 to 2n/2 − 1:
            • A[i] = F(h_in, M(i))
            • B[i] = F(h_tmp, M(i))
    3. Find i, j such that A[i] = B[j]
    4. Return colliding messages (M(i), q||q||...||q||M(j)), and the resulting intermediate
    hash F(h_in, M(i)).
    
    Instead of building two giant lists and then looking for collisions after we're done (which is not guaranteed to 
    succeed, since 2^n/2 is just the average runtime) we'll do this using maps. This will return as soon as we find a 
    collision, and will keep looking if it takes more than 2^n/2 iterations.
    """
    A = dict()
    B = dict()

    while True:
        m = os.urandom(16)
        a = F(h_in, m)
        b = F(h_tmp, m)
        A[a] = m
        B[b] = m

        if a in B:
            return Collision(m0=m, m1=prefix + B[a], h_in=h_in, h_tmp=h_tmp, result=a)
        elif b in A:
            return Collision(m0=A[b], m1=prefix + m, h_in=h_in, h_tmp=h_tmp, result=b)


def make_expandable_message(h_in, k):
    """
    ALGORITHM: MakeExpandableMessage(h_in, k)
    Make a (k, k + 2k − 1)-expandable message.
    Variables:
    1. h_tmp = the current intermediate hash value.
    2. C = a list of pairs of messages of different lengths; C[i][0] is the first
    message of pair i, while C[i][1] is that pair’s second message.
    Steps:
        1. Let h_tmp = h_in.
        2. For i = 0 to k − 1:
            – (m0, m1, h_tmp) = FindCollision(2i + 1, h_tmp)
            – C[k − i − 1][0] = m0
            – C[k − i − 1][1] = m1
        3. Return the list of message pairs C.
    Work: k × 2n/2+1 + 2k ≈ k × 2 n/2+1 compression function calls.
    """
    h_tmp = h_in
    collisions = []
    for i in range(k - 1):
        c = find_collision(2*i + 1, h_tmp)
        h_tmp = c.h_tmp
        collisions.append(c)
    return collisions


def produce_message(C, k, L):
    """
    ALGORITHM: ProduceMessage(C, k, L)
    Produce a message of length L, if possible, from the expandable message
    specified by (C, k).

    Variables:
        1. L = desired message length.
        2. k = parameter specifying that C contains a (k, k + 2k − 1)-expandable message.
        3. C = a k × 2 array of message fragments of different lengths.
        4. M = the message to be constructed.
        5. T = a temporary variable holding the remaining length to be added.
        6. S[0..k − 1] = a sequence of bits from T.
        7. i = an integer counter.

    Work: Negligible (about k table lookups and string copying operations).
    """

    """
    1. Start with an empty message M = ∅.
    """
    M = b''

    """
    2. If L > 2^k + k − 1 or L < k, return an error condition.
    """
    if L > 2 ** k + k - 1:
        raise ValueError(f"L is too big: L={L}, max={2 * k + k - 1}")

    if L < k:
        raise ValueError(f"L must be bigger than k: L={L}, k={k}")

    """
    3. Let T = L − k.
    4. Let S = the bit sequence of T, from low-order to high-order bits.
    """
    T = L - k
    S = f'{T:b}'.zfill(T)[::-1]  # binary representation, flip so low-order comes first

    """
    5. Concatenate message fragments from the expandable message together
    until we get the desired message length. Note that this is very similar to
    writing T in binary.
        – for i = 0 to k − 1:
            • if S[i] = 0 then M = M||C[i][0]
            • else M = M||C[i][1]
    6. Return M.
    """
    for i in range(k - 1):
        if S[i] == '0':
            M = M + C[i].m0
        else:
            M = M + C[i].m1

    return M


def long_message_attack(target):
    """
    ALGORITHM: LongMessageAttack(Mtarget)
    Find the second preimage for a message of 2^k + k + 1 blocks.

    Variables:
        1. Mtarget = the message for which a second preimage is to be found.
        2. M_link = a message block used to link the expandable message to some
        point in the target message’s sequence of intermediate hash values.
        3. A = a list of intermediate hash values
        4. h_exp = intermediate chaining value from processing an expandable message.

    Steps:
    1. C = MakeExpandableMessage(k)

    2. h_exp = the intermediate hash value after processing the expandable message
    in C.

    3. Compute the intermediate hash values for Mtarget:
        – h[−1] = the IV for the hash function
        – m[i] = the ith message block of Mtarget.
        – h[i] = F(h[i−1], m[i]), the ith intermediate hash output block. Note
        that h will be organized in some searchable structure for the attack,
        such as a hash table, and that elements h[0, 1, ..., k] are excluded
        from the hash table, since the expandable message cannot be made
        short enough to accommodate them in the attack.

    4. Find a message block that links the expandable message to one of the
    intermediate hash values for the target message after the kth block.
        – Try linking messages M_link until F(h_exp, M_link) = h[j] for some k + 1 ≤ j ≤ 2^k + k + 1.

    5. Use the expandable message to produce a message M∗ that is j−1 blocks long.

    6. Return second preimage M∗||M_link||m[j + 1]||m[j + 2]...m[2^k + k + 1]
    (if j = 2^k + k + 1, then no original message blocks are included in the
    second preimage).
    """


def main():
    """
    todo: Writeup
    """

    # test find_collision
    msg = (b'The major feature you want in your hash function is collision-resistance. That is, it should be hard to '
           b'generate collisions, and it should be really hard to generate a collision for a given hash.')

    # h = F(DEFAULT_IV, msg)
    k = len(msg) // 16  # todo: +1??
    c = find_collision(num_blocks=k, iv=DEFAULT_IV)

    assert F(c.h_in, c.m0) == F(c.h_in, c.m1)

    # test make_expandable_message
    C = make_expandable_message(DEFAULT_IV, k)

    # produce message
    M = produce_message(C, k, len(msg))

    print(len(M))
    print(len(msg))


def bad_pad(m):
    """
    Pads a message out to the end with zeros; does not use the appropriate Merkle Damgard padding that includes the
    message length.
    """
    return m + ('\x00' * len(m) % 16)


if __name__ == '__main__':
    main()

"""
Kelsey and Schneier's Expandable Messages
One of the basic yardsticks we use to judge a cryptographic hash function is its resistance to second preimage
attacks. That means that if I give you x and y such that H(x) = y, you should have a tough time finding x' such that
H(x') = H(x) = y.

How tough? Brute-force tough. For a 2^b hash function, we want second preimage attacks to cost 2^b operations.

This turns out not to be the case for very long messages.

Consider the problem we're trying to solve: we want to find a message that will collide with H(x) in the very last
block. But there are a ton of intermediate blocks, each with its own intermediate hash state.

What if we could collide into one of those? We could then append all the following blocks from the original message
to produce the original H(x). Almost.

We can't do this exactly because the padding will mess things up.

What we need are expandable messages.

In the last problem we used multicollisions to produce 2^n colliding messages for n*2^(b/2) effort. We can use the
same principles to produce a set of messages of length (k, k + 2^k - 1) for a given k.

Here's how:

Starting from the hash function's initial state, find a collision between a single-block message and a message of
2^(k-1)+1 blocks. DO NOT hash the entire long message each time. Choose 2^(k-1) dummy blocks, hash those, then focus
on the last block.
Take the output state from the first step. Use this as your new initial state and find another collision between a
single-block message and a message of 2^(k-2)+1 blocks.
Repeat this process k total times. Your last collision should be between a single-block message and a message of
2^0+1 = 2 blocks.
Now you can make a message of any length in (k, k + 2^k - 1) blocks by choosing the appropriate message (short or
long) from each pair.

Now we're ready to attack a long message M of 2^k blocks.

Generate an expandable message of length (k, k + 2^k - 1) using the strategy outlined above.
Hash M and generate a map of intermediate hash states to the block indices that they correspond to.
From your expandable message's final state, find a single-block "bridge" to intermediate state in your map. Note
the index i it maps to.
Use your expandable message to generate a prefix of the right length such that len(prefix || bridge || M[i..]) = len(M).
The padding in the final block should now be correct, and your forgery should hash to the same value as M.
"""