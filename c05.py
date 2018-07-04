from binascii import hexlify

k = b"ICE"
phrase = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
want = b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"


def encrypt(message, key):
    """
    Encrypts message with key using a rotating XOR of one character of the key against one character
    of the message. Same operation also decrypts.
    """
    return bytes(
        [message[i] ^ key[i % len(key)] for i in range(len(message))]
    )


def main():
    # encrypt with rotating key
    ciphertext = encrypt(phrase, k)

    # make sure we got what we wanted
    assert hexlify(ciphertext) == want


if __name__ == '__main__':
    main()

"""
Implement repeating-key XOR

Here is the opening stanza of an important work of the English language:

Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal

Encrypt it, under the key "ICE", using repeating-key XOR.

In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd 
against I, the next C, the next E, then I again for the 4th byte, and so on.

It should come out to:

0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
"""