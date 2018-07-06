from pals.ciphers import aes_ecb_decrypt
from base64 import b64decode


def main():
    # open file and decrypt
    with open('files/c7.txt', 'rb') as f:
        ciphertext = b64decode(f.read())
        plaintext = aes_ecb_decrypt(ciphertext, b'YELLOW SUBMARINE')

    # print result
    print(plaintext)


if __name__ == '__main__':
    main()

'''
AES in ECB mode
The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key

"YELLOW SUBMARINE".
(case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes 
long, and now you do too).

Decrypt it. You know the key, after all.

Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
'''