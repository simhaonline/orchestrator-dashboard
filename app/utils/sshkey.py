import base64
import binascii
import struct

def generate_ssh_key():
    from cryptography.hazmat.primitives import serialization as crypto_serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend as crypto_default_backend

    key = rsa.generate_private_key(
        backend=crypto_default_backend(),
        public_exponent=65537,
        key_size=2048
    )
    private_key = key.private_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PrivateFormat.PKCS8,
        crypto_serialization.NoEncryption())
    public_key = key.public_key().public_bytes(
        crypto_serialization.Encoding.OpenSSH,
        crypto_serialization.PublicFormat.OpenSSH
    )

    return private_key, public_key

def check_ssh_key(key):
    # credits to: https://gist.github.com/piyushbansal/5243418

    array = key.split()

    # Each rsa-ssh key has 3 different strings in it, first one being
    # typeofkey second one being keystring third one being username .
    if len(array) != 3:
        return 1

    typeofkey = array[0]
    string = array[1]
    # username = array[2]

    # must have only valid rsa-ssh key characters ie binascii characters
    try:
        data = base64.decodebytes(string)
    except binascii.Error:
        return 1

    a = 4
    # unpack the contents of data, from data[:4] , it must be equal to 7 , property of ssh key .
    try:
        str_len = struct.unpack('>I', data[:a])[0]
    except struct.error:
        return 1

    # data[4:11] must have string which matches with the typeofkey , another ssh key property.
    if data[a:a + str_len] == typeofkey and int(str_len) == int(7):
        return 0
    else:
        return 1