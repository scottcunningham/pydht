# Adapted from examples from:
# https://bitbucket.org/brendanlong/python-encryption
# Released into the Public Domain

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto import Random
from Crypto.Hash import HMAC
import base64
import json

# We keep the salt defined to be the same since this is just a proof-of-contept
SALT = "12345678"
ITERATIONS = 100000
KEY_LENGTH_BYTES = 16  # 16 * 8 = 128bit key

def make_key(password, iterations=ITERATIONS):
    """
       password - The password.
       iterations - The number of iterations of PBKDF2 (default=100000).

       returns a key
    """
    key = PBKDF2(password, SALT, dkLen=KEY_LENGTH_BYTES, count=iterations)
    return key

def encrypt(message, key):
    # IV needs to change every time
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    ciphertext = cipher.encrypt(message)
    return (ciphertext, iv)

def make_hmac(message, key):
    """Creates an HMAC from the given message, using the given key. Uses
       HMAC-MD5.
       message - The message to create an HMAC of.
       key - The key to use for the HMAC (at least 16 bytes).

       returns A hex string of the HMAC.
    """
    h = HMAC.new(key)
    h.update(message)
    return h.hexdigest()

def decrypt(ciphertext, key, iv):
    """Decrypts a given ciphertext with the given key, using AES-CFB.
       message - The ciphertext to decrypt (byte string).
       key - The AES key (16 bytes).
       iv - The original IV used for encryption.

       returns The cleartext (byte string)
    """
    cipher = AES.new(key, AES.MODE_CFB, iv)
    msg = cipher.decrypt(ciphertext)
    return msg


def do_encrypt(password, message):
    aes_key = make_key(password)
    hmac_key = make_key(password)
    ciphertext, iv = encrypt(message, aes_key)
    hmac = make_hmac(ciphertext, hmac_key)

    output = { "hmac": hmac }
    for key, value in ("ciphertext", ciphertext), ("iv", iv):
        output[key] = base64.b64encode(value).decode("utf-8")
    output_data = json.dumps(output).encode("utf-8")
    return output_data

def do_decrypt(password, message):
    data = json.loads(message.decode("utf-8"))
    ciphertext = base64.b64decode(data["ciphertext"])
    iv = base64.b64decode(data["iv"])

    aes_key = make_key(password)
    hmac_key = make_key(password)
    hmac = make_hmac(ciphertext, hmac_key)
    if hmac != data["hmac"]:
        print("HMAC doesn't match. Either the password was wrong, or the message was altered")
        raise ValueError
    output_data = decrypt(ciphertext, aes_key, iv)
    return output_data
