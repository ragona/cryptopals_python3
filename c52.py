import os
from pals.ciphers import pad, aes_ecb_encrypt
from pals.utils import clock, do_cprofile


DEFAULT_IV = b'\x00' * 16


class Collision:
    def __init__(self, a, b, initial_state, resulting_hash):
        self.a = a
        self.b = b
        self.initial_state = initial_state
        self.resulting_hash = resulting_hash

    def __str__(self):
        return f"Collision({self.a}, {self.b}, {self.initial_state})"


def merkle_damgard(message, iv, size):
    """
    Variably shitty hash function. Use small sizes for guaranteed easy collisions.
    """
    if len(iv) < 16:
        iv = pad(iv, 16)

    if len(message) < 16:
        message = pad(message)

    for m in chunks(message):
        iv = aes_ecb_encrypt(m, iv, nopad=True)
    return iv[:size]


def shitty_hash(message, iv=DEFAULT_IV):
    return merkle_damgard(
        message=message,
        iv=iv,
        size=2
    )


def only_slightly_less_shitty_hash(message, iv=DEFAULT_IV):
    return merkle_damgard(
        message=message,
        iv=iv,
        size=3
    )


# @do_cprofile
@clock
def find_collision(H):

    hashes = dict()

    # look for another block that gets us the same result
    while True:

        r = random_bytes()
        h = shitty_hash(r, H)

        if h in hashes and r != hashes[h]:

            return Collision(
                a=r,
                b=hashes[h],
                initial_state=H,
                resulting_hash=h)

        else:
            hashes[h] = r


def gather_collisions(H):

    # find a single initial collision
    collision = find_collision(H)

    # find a bunch more collisions, advancing the state each time (why does advancing the state matter?)
    while True:
        collision = find_collision(collision.resulting_hash)
        yield collision


def main():
    """
    todo: Add writeup
    """

    for c in gather_collisions(DEFAULT_IV):

        a = only_slightly_less_shitty_hash(c.a, c.initial_state)
        b = only_slightly_less_shitty_hash(c.b, c.initial_state)

        if a == b:
            print("Found collision in stronger hash")
            break


def chunks(M):
    msg_len = len(M)
    for i in range(0, msg_len, 16):
        yield M[i: i + 16]


def random_bytes():
    return os.urandom(16)


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
