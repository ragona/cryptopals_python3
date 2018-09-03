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
    q = os.urandom(16)
    h_in = iv
    h_tmp = iv

    """
    1. Compute the starting hash for the α-block message by processing α − 1
    dummy message blocks:
        – h_tmp = h_in.
        – For i = 0 to α − 2:
            • h_tmp = F(h_tmp, q)
    
    We're priming the chaining value so that we can focus on the last block in step 2. 
    """
    for i in range(num_blocks - 2):
        h_tmp = F(h_tmp, q)

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
            return Collision(m0=m, m1=B[a], h_in=h_in, h_tmp=h_tmp, result=a)
        elif b in A:
            return Collision(m0=A[b], m1=m, h_in=h_in, h_tmp=h_tmp, result=b)


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


def main():
    """
    todo: Writeup
    """

    # test find_collision
    msg = (b'The major feature you want in your hash function is collision-resistance. That is, it should be hard to '
           b'generate collisions, and it should be really hard to generate a collision for a given hash.')

    h = F(DEFAULT_IV, msg)
    c = find_collision(num_blocks=len(msg) // 16, iv=DEFAULT_IV)

    assert F(c.h_in, c.m0) == F(c.h_tmp, c.m1)

    # test make_expandable_message
    C = make_expandable_message(DEFAULT_IV, len(msg) // 16)

    print(C)


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

We can't do this exactly because the padding will mess th_ings up.

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