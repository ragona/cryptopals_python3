from binascii import hexlify
from pals import utils


key = b'YELLOW SUBMARINE'
iv = b'\x00' * 16


def cbc_hash(s):
    """
    Hex encoded "hash" of CBC-MAC(s)
    """
    return hexlify(
        utils.aes_cbc_mac(s, key, iv, no_pad=True)
    )


def length_extension_forgery(original, mac, extension):
    """
    Does the extension forgery in reverse; we start with the new payload ('extension'), then generate
    a block that resets the state of the MAC so that when hashed in the future the result ends up being
    the same as the original hash.
    """
    return extension + utils.xor(mac, original[:16]) + original[16:]


def main():
    """
    We're imagining here that we can talk the server into doing this CBC-MAC hash to the 'bad' payload.
    Once we have that, we can use that to create a block that will reset the state of the CBC process
    when appended to the new payload.
    """
    # original message and mac
    original = utils.pad(b"alert('MZA who was that?');\n", 16)

    # the "extension" (we're actually gonna have this at the beginning of the message)
    extension = b"alert('Ayo, the Wu is back!');//"  # '//' gets us to exactly 32 and also negates the reset block
    ext_mac = utils.aes_cbc_mac(extension, key, iv, no_pad=True)
    payload = length_extension_forgery(original, ext_mac, extension)

    # make sure these match
    assert cbc_hash(payload) == cbc_hash(original)


if __name__ == '__main__':
    main()

'''
Hashing with CBC-MAC
Sometimes people try to use CBC-MAC as a hash function.

This is a bad idea. Matt Green explains:

To make a long story short: cryptographic hash functions are public functions (i.e., no secret key) that have
the property of collision-resistance (it's hard to find two messages with the same hash). MACs are keyed functions
that (typically) provide message unforgeability -- a very different property. Moreover, they guarantee this only
when the key is secret.

Let's try a simple exercise.

Hash functions are often used for code verification. This snippet of JavaScript (with newline):

alert('MZA who was that?');
Hashes to 296b8d7cb78a243dda4d0a61d33bbdd1 under CBC-MAC with a key of "YELLOW SUBMARINE" and a 0 IV.

Forge a valid snippet of JavaScript that alerts "Ayo, the Wu is back!" and hashes to the same value. Ensure that it
runs in a browser.

Extra Credit
Write JavaScript code that downloads your file, checks its CBC-MAC, and inserts it into the DOM iff it matches
the expected hash.
'''