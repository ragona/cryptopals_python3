from base64 import b64decode
from Crypto.Cipher import AES
from pals.utils import pad, unpad


def aes_cbc_encrypt(data, key, iv):
    # make data fit within 16 byte blocks
    data = pad(data, 16)
    # prepare cipher
    cipher = AES.new(key, AES.MODE_ECB)
    # resulting ciphertext buffer that we'll return
    ciphertext = bytearray()
    # first block is the iv
    block = iv
    # do the encryption
    for i in range(0, len(data), 16):
        # get the plaintext block
        plaintext = data[i: i + 16]
        # xor it with the previous block
        xord_block = bytes([plaintext[i] ^ block[i] for i in range(16)])
        # store that ciphertext block for use next iteration
        block = cipher.encrypt(xord_block)
        # append to overall ciphertext
        ciphertext += block
    # return immutable bytes object rather than bytearray
    return bytes(ciphertext)


def aes_cbc_decrypt(data, key, iv):
    cipher = AES.new(key, AES.MODE_ECB)
    # resulting plaintext buffer
    plaintext = bytearray()
    # the block we'll xor with the decrypted (this will be either the iv or some ciphertext)
    xor_block = iv
    # do the decryption
    for i in range(0, len(data), 16):
        # get the ciphertext block
        ciphertext = data[i: i + 16]
        # decrypt it; this gets us the block that has been xor'd
        decrypted = cipher.decrypt(ciphertext)
        # undo the xor to get the plaintext
        pt_block = bytes([xor_block[i] ^ decrypted[i] for i in range(16)])
        # store that ciphertext; we'll use it next round
        xor_block = ciphertext
        # append to overall plaintext
        plaintext += pt_block
    # return immutable bytes object rather than bytearray (and unpad)
    return bytes(unpad(plaintext))


def main():
    key = b'YELLOW SUBMARINE'
    iv = b'0' * 16

    with open('files/c10.txt', 'rb') as f:
        # read the file and get the raw bytes
        data = b64decode(f.read())
        # decrypt it
        dec = aes_cbc_decrypt(data, key, iv)
        # re-encrypt it
        enc = aes_cbc_encrypt(dec, key, iv)
        # verify our implementation works by asserting that we should back to the original bytes
        assert enc == data


if __name__ == '__main__':
    main()

'''
Implement CBC mode
CBC mode is a block cipher mode that allows us to encrypt 
irregularly-sized messages, despite the fact that a block 
cipher natively only transforms individual blocks.

In CBC mode, each ciphertext block is added to the next 
plaintext block before the next call to the cipher core.

The first plaintext block, which has no associated previous 
ciphertext block, is added to a "fake 0th ciphertext block" 
called the initialization vector, or IV.

Implement CBC mode by hand by taking the ECB function you 
wrote earlier, making it encrypt instead of decrypt (verify 
this by decrypting whatever you encrypt to test), and using 
your XOR function from the previous exercise to combine them.

The file here is intelligible (somewhat) when CBC decrypted against 
"YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)
'''