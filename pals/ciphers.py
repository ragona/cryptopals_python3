from Crypto.Cipher import AES
from pals.utils import pad
from pals.utils import xor


def aes_ecb_encrypt(data, key):
    data = pad(data, (len(data) // 16 + 1) * 16)
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(data)


def aes_ecb_decrypt(data, key):
    return AES.new(key, AES.MODE_ECB).decrypt(data)


def aes_cbc_encrypt(data, key, iv):
    cipher = AES.new(key, AES.MODE_ECB)
    block_size = len(iv)
    results = bytes()
    ciphertext = iv
    data = pad(data, 16)
    for i in range(0, len(data), block_size):
        plaintext = data[i: i + block_size]
        xord = bytes([plaintext[i] ^ ciphertext[i] for i in range(block_size)])
        ciphertext = cipher.encrypt(xord)
        results += ciphertext
    return results


# just returns the last block
def aes_cbc_mac(data, key, iv, no_pad=False):
    cipher = AES.new(key, AES.MODE_ECB)
    block_size = len(iv)
    ciphertext = iv
    if not no_pad:
        data = pad(data, 16)
    for i in range(0, len(data), block_size):
        plaintext = data[i: i + block_size]
        xord = bytes([plaintext[i] ^ ciphertext[i] for i in range(block_size)])
        ciphertext = cipher.encrypt(xord)

    return ciphertext


def aes_cbc_decrypt(data, key, iv):
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)


def ctr(data, key, nonce):
    output = bytes()
    for i in range(len(data) // 16 + 1):
        counter = (i).to_bytes(8, byteorder='little')
        keystream = AES.new(key, AES.MODE_ECB).encrypt(nonce + counter)
        block = data[i * 16 : i * 16 + 16]
        output += xor(block, keystream)
    return output

