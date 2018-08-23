import zlib
import os
import string
import random
from math import inf
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
    return bytes((
        "POST / HTTP / 1.1\n"
        "Host: google.com\n"
        "Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\n"
        f"Content-Length: {len(post)}\n"
        f"{post}"
    ), "utf-8")


def main():
    """
    This works but it is NOT very resilient. It seems to only work in this narrow case.
    Fixing it next. The bit that deals with CBC padding appears to be fine; the part
    that isn't working is when the correct guess does not land on a byte boundary. I'm
    not really sure what to do to fix that. I tried guessing two bytes at a time and it
    didn't really help.
    """

    known_plaintext = "session_id="
    base64charset = string.ascii_letters + string.digits + "/+=\n"

    # padding to make CBC play nice -- we're trying to pad out so that the correct guess is one block smaller
    pad_length = 0
    starting_length = oracle(known_plaintext)
    for j in range(16):
        shimmed_length = oracle(known_plaintext + "*" * j)
        if shimmed_length != starting_length:
            pad_length = j - 1
            break

    # pad with some value we won't see in a b64 string
    pad = "*" * pad_length

    def guess_character(known):
        best_guess = None
        # make one bad guess; we need to beat this or it indicates we're stuck
        shortest_len = oracle(known + "#" + pad)
        for c in base64charset:
            compressed_len = oracle(known + c + pad)
            if compressed_len < shortest_len:
                shortest_len = compressed_len
                best_guess = c
        return best_guess

    # loop until we find the end of the line the session key is on
    guess = None
    while guess != '\n':
        guess = guess_character(known_plaintext)
        if guess is not None:
            known_plaintext += guess
        else:
            print("stuck")
            break

    print(bytearray(known_plaintext, "utf-8"))


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
