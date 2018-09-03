import os
from pals.ciphers import pad, aes_ecb_encrypt
from pals.utils import clock, do_cprofile


DEFAULT_IV = b'\x00' * 16


class Collision:

    def __init__(self, a, b, initial_state, resulting_hash):
        """
        f(iv=initial_state, msg=a) == f(iv=initial_state, msg=b) == resulting_hash

        :param a: Message
        :param b: Message
        :param initial_state: Initial IV
        :param resulting_hash: The collision
        """
        self.a = a
        self.b = b
        self.initial_state = initial_state
        self.resulting_hash = resulting_hash

    def __str__(self):
        return f"Collision(hash={self.resulting_hash}, a={self.a}, b={self.b}, iv={self.initial_state})"


def merkle_damgard(message, iv, size):
    """
    Variably shitty iterative hash function. Use small sizes for easy collisions. 'iv' is equal to 'H' or the initial
    state as described in the various papers on this topic. Note that message and IV are flipped from f(IV, m).
    """

    if len(iv) % 16 != 0:
        iv = pad(iv, 16)

    if len(message) % 16 != 0:
        message = pad(message)

    def chunks(n):
        return (message[i: i + n] for i in range(0, len(message), n))

    for m in chunks(16):
        iv = aes_ecb_encrypt(m, iv, nopad=True)

    return iv[:size]


# @do_cprofile
@clock
def colliding_pair(H, f):
    """
    Finds two things that collide with each other when they use H as the initial chaining block.

    :param H: Initial state (the "IV")
    :param f: The hashing function to use
    """

    hashes = dict()  # { hash: message }

    while True:

        m = os.urandom(16)
        h = f(message=m, iv=H)

        if h in hashes and m != hashes[h]:
            return Collision(
                a=m,
                b=hashes[h],
                initial_state=H,
                resulting_hash=h)
        else:
            hashes[h] = m


def gather_collisions(H, f):
    """
    This function yields collisions as soon as it finds them. This is a bit of a departure from the paper and the
    suggestion in the text (which suggest gathering 2^t collisions) but it feels more natural to me.
    """
    # find a single initial collision
    collision = colliding_pair(H, f)
    yield collision

    # find a bunch more collisions, advancing the initial state (H) each time
    while True:
        collision = colliding_pair(collision.resulting_hash, f)
        yield collision


def main():
    """
    This attack is about proving why it isn't safe to strengthen a hash by combining a weak hash and a stronger hash.
    This method will produce a pair of inputs plus an initial state (IV, or H) that will collide under BOTH functions.
    The average runtime is 2^b2-b1 calls to the function that generates colliding pairs, where b2 is the bitlength of
    the stronger hash, and b1 is the bitlength of the weaker hash. For example, with b1 of 16 and b2 of 24, you'll
    usually find a multi-collision in around 256 iterations. If you bump b2 up to 32 bits, it'll average 65536 runs.

    To be honest, I struggled with this one. I had a bunch of incorrect assumptions going into it, I got frustrated,
    I made a dumb mistake with the runtime of finding colliding pairs, and I'm STILL not totally sure that this is what
    I was supposed to produce. I'm like... 85% sure this is correct.
    """

    """
    From Joux (pg. 4): f(f(IV, b0), b1) = f(f(IV, b0), b1') = f(f(IV, b0'), b1) = f(f(IV, b0'), b1') 
    Note: non-prime (b0) represented by a in the Collision, prime (b0') represented by b.
    """
    def f(iv, message):
        return merkle_damgard(
            message=message,
            iv=iv,
            size=2)

    C = gather_collisions(H=DEFAULT_IV, f=f)
    b0 = next(C)
    b1 = next(C)

    assert f(f(DEFAULT_IV, b0.a), b1.a) \
        == f(f(DEFAULT_IV, b0.a), b1.b) \
        == f(f(DEFAULT_IV, b0.b), b1.a) \
        == f(f(DEFAULT_IV, b0.b), b1.b)

    """
    Prove this out by building a more expensive (but not too expensive) hash function to pair with the one you just 
    used. Find a pair of messages that collide under both functions. Measure the total number of calls to the collision 
    function.
    """

    def g(message, iv):
        return merkle_damgard(
            message=message,
            iv=iv,
            size=3
        )

    for c in gather_collisions(H=DEFAULT_IV, f=f):
        a = g(message=c.a, iv=c.initial_state)
        b = g(message=c.b, iv=c.initial_state)

        if a == b:
            print("Found collision in stronger hash")
            break


if __name__ == '__main__':
    main()

"""
Iterated Hash Function Multicollisions
While we're on the topic of hash functions...

The major feature you want in your hash function is collision-resistance. That is, it should be hard to generate
collisions, and it should be really hard to generate a collision for a given hash (aka preimage).

Iterated hash functions have a problem: the effort to generate lots of collisions scales sublinearly.

What's an iterated hash function? For all intents and purposes, we're talking about the Merkle-Damgard construction.
It looks like this:

function MD(M, H, C):
  for M[i] in pad(M):
    H := C(M[i], H)
  return H
For message M, initial state H, and compression function C.

This should look really familiar, because SHA-1 and MD4 are both in this category. What's cool is you can use this
formula to build a makeshift hash function out of some spare crypto primitives you have lying around (e.g. C = AES-128).

Back on task: the cost of collisions scales sublinearly. What does that mean? If it's feasible to find one collision,
it's probably feasible to find a lot.

How? For a given state H, find two blocks that collide. Now take the resulting hash from this collision as your new H
and repeat. Recognize that with each iteration you can actually double your collisions by subbing in either of the two
blocks for that slot.

This means that if finding two colliding messages takes 2^(b/2) work (where b is the bit-size of the hash function),
then finding 2^n colliding messages only takes n*2^(b/2) work.

Let's test it. First, build your own MD hash function. We're going to be generating a LOT of collisions, so don't knock
yourself out. In fact, go out of your way to make it bad. Here's one way:

Take a fast block cipher and use it as C.
Make H pretty small. I won't look down on you if it's only 16 bits. Pick some initial H.
H is going to be the input key and the output block from C. That means you'll need to pad it on the way in and drop
bits on the way out.
Now write the function f(n) that will generate 2^n collisions in this hash function.

Why does this matter? Well, one reason is that people have tried to strengthen hash functions by cascading them
together. Here's what I mean:

Take hash functions f and g.
Build h such that h(x) = f(x) || g(x).
The idea is that if collisions in f cost 2^(b1/2) and collisions in g cost 2^(b2/2), collisions in h should come to
the princely sum of 2^((b1+b2)/2).


But now we know that's not true!

Here's the idea:

Pick the "cheaper" hash function. Suppose it's f.
Generate 2^(b2/2) colliding messages in f.
There's a good chance your message pool has a collision in g.
Find it.
And if it doesn't, keep generating cheap collisions until you find it.

Prove this out by building a more expensive (but not too expensive) hash function to pair with the one you just used.
Find a pair of messages that collide under both functions. Measure the total number of calls to the collision function.
"""
