from Crypto.Cipher import AES
from pals.utils import pad, unpad, xor


def aes_ecb_encrypt(data, key, nopad=False):
    if not nopad:
        data = pad(data, (len(data) // 16 + 1) * 16)
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(data)


def aes_ecb_decrypt(data, key):
    return AES.new(key, AES.MODE_ECB).decrypt(data)


def aes_cbc_encrypt(data, key, iv):
    data = pad(data, 16)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = bytearray()
    block = iv
    for i in range(0, len(data), 16):
        plaintext = data[i: i + 16]
        xord_block = bytes([plaintext[i] ^ block[i] for i in range(16)])
        block = cipher.encrypt(xord_block)
        ciphertext += block
    return bytes(ciphertext)


def aes_cbc_decrypt(data, key, iv):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = bytearray()
    xor_block = iv
    for i in range(0, len(data), 16):
        ciphertext = data[i: i + 16]
        decrypted = cipher.decrypt(ciphertext)
        pt_block = bytes([xor_block[i] ^ decrypted[i] for i in range(16)])
        xor_block = ciphertext
        plaintext += pt_block
    return bytes(unpad(plaintext))


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


def ctr(data, key, nonce):
    output = bytes()
    for i in range(len(data) // 16 + 1):
        counter = (i).to_bytes(8, byteorder='little')
        keystream = AES.new(key, AES.MODE_ECB).encrypt(nonce + counter)
        block = data[i * 16 : i * 16 + 16]
        output += xor(block, keystream)
    return output

