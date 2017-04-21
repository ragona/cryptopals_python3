from Crypto.Cipher import AES
from Crypto import Random
from pals import utils


import base64

with open('files/c7.txt', 'rb') as f:
    print(utils.aes_ecb_decrypt(base64.b64decode(f.read()), b'YELLOW SUBMARINE', b''))


'''
AES in ECB mode
The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key

"YELLOW SUBMARINE".
(case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).

Decrypt it. You know the key, after all.

Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
'''