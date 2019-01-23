from Crypto import Random
from pals import utils
import base64

b64unknown = b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
rand_key = Random.get_random_bytes(16)
unknown = base64.b64decode(b64unknown)

def black_box(user_input):
    return utils.aes_ecb_encrypt(user_input + unknown, rand_key)


# ecb byte at a time
# f should be a function that takes a byte string
# and returns an ecb encrypted byte string
def ecb_byte_aat(f):
    # get blocksize first
    blocksize = get_block_size(f)

    # solve the prefix (if any)
    # we need overall length and the length of the tail
    # prefix_len will be multiple of blocksize, tail_len
    # will be the number of bytes needed to pad the prefix
    # so that we can send in our input below cleanly at the
    # start of a block
    def solve_prefix():
        for i in range(blocksize):
            pad = b'A' * (i + blocksize * 2)
            blocks = get_blocks(f(pad), 16)
            for j in range(len(blocks) - 1):
                if blocks[j] == blocks[j + 1]:
                    return(j * blocksize, i)
        raise Exception("sorry pal")

    prefix_len, tail_len = solve_prefix()

    # we're gonna read the unknown portion by eating
    # into it one byte at a time by sending in known
    # input plus sized padding such that we can
    # randomize the very last byte of input
    solved = b''
    pre = b'A' * tail_len  # number of bytes to pad out the prefix block
    pad = b'A' * blocksize
    while True:
        # pad is the empty bytes at the front
        pad = b'A' * ((blocksize - 1 - (len(solved) % blocksize)))
        # overall size, must be will be a multiple of blocksize
        # includes the one byte that we're randomizing, as well
        # as the total length of the prefix bytes
        size = prefix_len + len(pad) + len(solved) + 1
        results = {}
        # send (pre + pad + solved + char) into the box, store
        # the first 'size' bytes in our results dict keyed
        # to the single byte that we used to get the result
        for j in range(0,255):
            test = f(pre + pad + solved + bytes([j]))
            results[test[0:size]] = bytes([j])
        # send JUST the pad into the black box but test
        # the same number of bytes off the front of the
        # result against the results table and see if
        # we have the a matching result in our dict
        pad_only = f(pre + pad)
        chunk = pad_only[0:size]
        if chunk in results:
            solved += results[chunk]
        else:
            break

    return solved


def main():
    result = ecb_byte_aat(black_box)
    print(result)


if __name__ == '__main__':
    main()

print( utils.ecb_byte_aat(black_box) )

'''
Byte-at-a-time ECB decryption (Simple)
Copy your oracle function to a new function that encrypts
buffers under ECB mode using a consistent but unknown key
(for instance, assign a single random key, once, to a global
variable).

Now take that same function and have it append to the
plaintext, BEFORE ENCRYPTING, the following string:

Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK

Spoiler alert.
Do not decode this string now. Don't do it.

Base64 decode the string before appending it. Do not base64
decode the string by hand; make your code do it. The point
is that you don't know its contents.

What you have now is a function that produces:

AES-128-ECB(your-string || unknown-string, random-key)
It turns out: you can decrypt "unknown-string" with repeated
calls to the oracle function!

Here's roughly how:

Feed identical bytes of your-string to the function 1 at a time
--- start with 1 byte ("A"), then "AA", then "AAA" and so on.
Discover the block size of the cipher. You know it, but do this
step anyway.

Detect that the function is using ECB. You already know, but
do this step anyways.

Knowing the block size, craft an input block that is exactly 1
byte short (for instance, if the block size is 8 bytes, make
"AAAAAAA"). Think about what the oracle function is going to put
in that last byte position.

Make a dictionary of every possible last byte by feeding different
strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB",
"AAAAAAAC", remembering the first block of each invocation.
Match the output of the one-byte-short input to one of the entries
in your dictionary. You've now discovered the first byte of
unknown-string.

Repeat for the next byte.
'''
