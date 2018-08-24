import zlib
import os
import string
import random
from salsa20 import Salsa20_xor
from pals.ciphers import aes_cbc_encrypt


def oracle(post):
    return len(encrypt(compress(format_request(post))))


def encrypt(data):
    return cbc_encrypt(data)


def cbc_encrypt(data):
    return aes_cbc_encrypt(
        data=data,
        key=os.urandom(16),
        iv=os.urandom(16)
    )


def stream_encrypt(data):
    key = os.urandom(32)
    iv = os.urandom(8)
    return Salsa20_xor(data, iv, key)


def compress(data):
    return zlib.compress(data)


def format_request(post):
    return bytes((
        "POST / HTTP / 1.1\n"
        "Host: google.com\n"
        "Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\n"
        f"Content-Length: {len(post)}\n"
        f"{post}"
    ), "utf-8")


def main():
    """
    This was a fun one. It seems deceptively simple, but it turns out there are a LOT of corner cases
    and ways for the effort to fail. I've solved a number of the common offenders that cause failures,
    but just play around with the response body and I'm sure you can find one that pisses this thing off.
    It's also very possible to just get a bad guess that leads the thing down an incorrect path, but if you
    can identify you're stuck and just start over it often gets it on a subsequent run. I often see that it has
    correctly found *A* string in the body (e.g. "sessionid=TmV2ZHost") which does compress better but is of course
    not actually the session key. Found a lot of edge cases by just messing with the body; the base case actually
    works really easily. (Even just changing "hapless" to "google" catches a byte boundary case.)

    Things I struggled with:
    - Guessing two bytes at a time didn't occur to me for a while to resolve byte boundary problems.
    - Padding is hard to get right -- 'AAAAAA' of course compresses well which can give confusing results.
      I suspect I still have some padding off by one problems in here.
    - This shit is not deterministic. I think zlib includes the timestamp or some shit?
    - If it guesses newline incorrectly the damned thing stops.
    - Repeated elements inside session key have a good chance of breaking everything. wtf.

    """
    known_plaintext = "session_id="
    chars_to_guess = string.ascii_letters + string.digits + "/+=\n"  # guess from b64 chars plus newline
    pairs_to_guess = pair_combos(chars_to_guess)

    while '\n' not in known_plaintext:
        guess = guess_from_iterable(iterable=chars_to_guess, known=known_plaintext)
        if guess is not None:
            known_plaintext += guess
        else:
            # Try a two byte guess to resolve misaligned compression
            pair_guess = guess_from_iterable(iterable=pairs_to_guess, known=known_plaintext)
            if pair_guess is not None:
                known_plaintext += pair_guess
            else:
                print(f"Restarting: failure at '{known_plaintext}'")
                known_plaintext = "session_id="

    print(bytes(known_plaintext, "utf-8"))


def guess_from_iterable(iterable, known):
    """
    This function uses the iterable provided to make guesses. It makes a bad guess, and then tries to beat that
    guess. Returns the first good guess it finds. This occasionally finds the wrong string; there are things other
    than the session key in the body, and sometimes it'll pick up on those.

    Currently we only guess one or two byte sizes, but this also supports guessing more bytes at a time. (I tried this,
    and it didn't resolve the case I was hoping it would resolve, so I don't know if that would ever have value.)
    """
    iterable_chunk_size = len(iterable[0])
    pad = find_padding(known, iterable_chunk_size)

    # baseline with a guess we know is wrong
    bad_guess = random_nonb64_string(iterable_chunk_size)
    incorrect_len = oracle(pad + known + bad_guess)

    for c in iterable:
        compressed_len = oracle(pad + known + c)
        if compressed_len < incorrect_len:
            return c

    return None


def find_padding(known, iter_len=1):
    """
    Generates random non-b64 strings and uses them to pad out and find the edge of the block.
    ---
    A randomly bad choice from random_nonb64_string seems like it could cause us to end up off-by-one with the
    padding choice, which would ruin everything. Also, you sometimes need more that 16 bytes of padding. That
    doesn't make sense to me, and I haven't dug into why. (Maybe it's the repeated char thing? Who knows.)
    """
    pad = None
    starting_length = oracle(known)
    for i in range(32):
        test_pad = random_nonb64_string(i)
        padded_length = oracle(known + test_pad)
        if padded_length != starting_length:
            pad = test_pad[:-iter_len]
            break
    return pad


def random_nonb64_string(length):
    """
    I think this has a potential bug where the compressor gets clever and manages to compress a repeated element,
    which could cause us to fail to find appropriate padding.
    """
    return ''.join(
        random.choices('!@#$%^&*(){}[]', k=length)
    )


def pair_combos(iterable):
    """
    This just brute forces the list of all possible pair permutations. Why not just use this itertools.permutations?
    Permutations doesn't include repeats -- you don't get 'aa', for example, so if you get a repeat in the session key
    that also happens to be in an area that requires two byte guesses you'll never get it.
    """
    pairs = set()
    for a in iterable:
        for b in iterable:
            pairs.add(a + b)
    return list(pairs)


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
