import base64
import hmac
import os

from Crypto.Cipher import AES
from Crypto.Hash import SHA256, SHA
from Crypto.Protocol.KDF import PBKDF2

from security.padding import PKCS7Encoder, PKCS5Encoder


def get_key(passphrase, salt=None, dkLen=32):
    if salt is None:
        salt = os.urandom(16)
    passphrase = SHA256.new(passphrase.encode('utf-8')).digest()
    key = PBKDF2(passphrase, salt, dkLen=dkLen)
    return key


def pkcs7_padding(data, block_size):
    pad = block_size - (len(data) % block_size)
    data += chr(pad) * pad
    return data


def pkcs7_unpadding(data, block_size):
    size = len(data)
    if size < block_size or size % block_size != 0:
        return None
    pad = ord(data[-1])
    if pad <= 0 or pad > block_size:
        return None
    for i in xrange(2, pad + 1):
        if ord(data[-i]) != pad:
            return None
    return data[:-pad]


if __name__ == '__main__':
    key = get_key(r'ASDASD$%', r'testsaltstr!@!@)!^', 32+16)

    data = PKCS7Encoder().encode('1234567890123456'.encode('utf-8'))
    # data = pkcs7_padding('1234567890123456', 16)

    # cipher = AES.new(key[:32], mode=AES.MODE_CBC, IV=key[32:])
    # cipher = AES.new(key, mode=AES.MODE_CBC, IV=key[:16])
    # encrypted_data = base64.b64encode(cipher.encrypt(data))
    # print encrypted_data

    cipher = AES.new(key[:32], mode=AES.MODE_CBC, IV=key[32:])
    # cipher = AES.new(key, mode=AES.MODE_CBC, IV=key[:16])
    decrypted_data = cipher.decrypt(base64.b64decode('3yrRYo4AlajXX3Q4Xui4mOiPVKlhj9pSBPtjLrb8uB8='))
    print decrypted_data
    print PKCS7Encoder().decode(decrypted_data)
