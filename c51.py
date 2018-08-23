import zlib
import os
import string
import itertools
import random
from pals.ciphers import aes_cbc_encrypt
from salsa20 import Salsa20_xor


def oracle(post):
    return len(encrypt(compress(format_request(post))))


def encrypt(data):
    return cbc_encrypt(data)
    # return stream_encrypt(data)


def stream_encrypt(data):
    key = os.urandom(32)
    iv = os.urandom(8)
    return Salsa20_xor(data, iv, key)


def cbc_encrypt(data):
    return aes_cbc_encrypt(
        data=data,
        key=os.urandom(16),
        iv=os.urandom(16)
    )


def compress(data):
    return zlib.compress(data)


def format_request(post):
    """
    'google.com' instead of 'hapless.com' compresses differently and makes this way harder. This means that the naive
    single character at a time approach will fail part of the way through recovering the session ID, so you need to
    bust up the compression byte boundary with a two byte guess approach. This is of course way more expensive, but
    it's a fun additional challenge.
    """
    return bytes((
        "POST / HTTP / 1.1\n"
        "Host: google.com\n"
        "Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\n"
        f"Content-Length: {len(post)}\n"
        f"{post}"
    ), "utf-8")


def main():
    """
    todo: Add writeup. WAIT. This shit isn't actually bombproof against different combos yet. Nooooo.
    """

    known_plaintext = "session_id="
    base64charset = string.ascii_letters + string.digits + "/+=\n"
    base64pairs = [''.join(pair) for pair in itertools.permutations(base64charset, 2)]

    # loop until we find the end of the line the session key is on
    while '\n' not in known_plaintext:
        # just guess single characters as our default
        guess = guess_from_iterable(base64charset, known_plaintext)
        if guess is not None:
            known_plaintext += guess
        else:
            # alright that didn't work, start guessing pairs
            pair_guess = guess_from_iterable(base64pairs, known_plaintext)
            if pair_guess is None:
                print("nooo")
                break
            else:
                known_plaintext += pair_guess

    print(bytearray(known_plaintext, "utf-8"))


def guess_from_iterable(iterable, known):
    # make one bad guess to initialize; we need to beat this or it indicates we're stuck
    bad_guess = ''.join(
        random.choices('!@#$%^&*(){}[]', k=len(iterable[0]))
    )
    pad = find_padding(known, len(iterable[0]))
    shortest_len = oracle(pad + known + bad_guess)
    best_guess = None

    for c in iterable:
        compressed_len = oracle(pad + known + c)
        if compressed_len < shortest_len:
            shortest_len = compressed_len
            best_guess = c
    return best_guess


def find_padding(known, iter_len=1):
    # padding to make CBC play nice -- we're trying to pad out so that the correct guess is one block smaller
    pad_length = 0
    starting_length = oracle(known)
    for j in range(16):
        shimmed_length = oracle("*" * j + known)
        if shimmed_length != starting_length:
            pad_length = j - iter_len
            break

    # pad with some value we won't see in a b64 string
    return "*" * pad_length


if __name__ == '__main__':
    main()

"""
Compression Ratio Side-Channel Attacks
Internet traffic is often compressed to save bandwidth. Until recently, this included HTTPS headers, and it still
includes the contents of responses.

Why does that matter?

Well, if you're an attacker with:

Partial plaintext knowledge and
Partial plaintext control and
Access to a compression oracle
You've got a pretty good chance to recover any additional unknown plaintext.

What's a compression oracle? You give it some input and it tells you how well the full message compresses,
i.e. the length of the resultant output.

This is somewhat similar to the timing attacks we did way back in set 4 in that we're taking advantage of incidental
side channels rather than attacking the cryptographic mechanisms themselves.

Scenario: you are running a MITM attack with an eye towards stealing secure session cookies. You've injected malicious
content allowing you to spawn arbitrary requests and observe them in flight. (The particulars aren't terribly
important, just roll with it.)

So! Write this oracle:

oracle(P) -> length(encrypt(compress(format_request(P))))
Format the request like this:

POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
Content-Length: ((len(P)))
((P))
(Pretend you can't see that session id. You're the attacker.)

Compress using zlib or whatever.

Encryption... is actually kind of irrelevant for our purposes, but be a sport. Just use some stream cipher. Dealer's
choice. Random key/IV on every call to the oracle.

And then just return the length in bytes.

Now, the idea here is to leak information using the compression library. A payload of "sessionid=T" should compress
just a little bit better than, say, "sessionid=S".

There is one complicating factor. The DEFLATE algorithm operates in terms of individual bits, but the final message
length will be in bytes. Even if you do find a better compression, the difference may not cross a byte boundary. So
that's a problem.

You may also get some incidental false positives.

But don't worry! I have full confidence in you.

Use the compression oracle to recover the session id.

I'll wait.

Got it? Great.

Now swap out your stream cipher for CBC and do it again.
"""
