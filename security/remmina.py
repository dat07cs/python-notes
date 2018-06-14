import base64
from Crypto.Cipher import DES3


def decrypt_password(password, secret):
    secret = base64.b64decode(secret)
    password = base64.b64decode(password)
    print len(secret)
    print len(password)

    return DES3.new(secret[:24], DES3.MODE_CBC, secret[24:]).decrypt(password)


if __name__ == '__main__':
    print decrypt_password('password', 'hLzEqMz2NcI5fMigrycTTc5oS0krfNrMgwJrw9/ftWQ=')
    # print decrypt_password('password', 'hLzEqMz2NcI5fMigrycTTc5oS0krfNrMgwJrw9/ftWQ=')
