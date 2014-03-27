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
SALT = bytes(12345678)
ITERATIONS = 1000
KEY_LENGTH = 128

def make_keys(password, salt=None, iterations=100000):
    """Generates two 128-bit keys from the given password using
       PBKDF2-SHA256.
       We use PBKDF2-SHA256 because we want the native output of PBKDF2 to be
       256 bits. If we stayed at the default of PBKDF2-SHA1, then the entire
       algorithm would run twice, which is slow for normal users, but doesn't
       slow things down for attackers.
       password - The password.
       salt - The salt to use. If not given, a new 8-byte salt will be generated.
       iterations - The number of iterations of PBKDF2 (default=100000).

       returns (k1, k2, salt, interations)
    """
    if salt is None:
        # Generate a random 8-byte salt
        salt = Random.new().read(8)

    # Generate a 32-byte (256-bit) key from the password
    key = PBKDF2(password, salt, 32, iterations)

    # Split the key into two 16-byte (128-bit) keys
    return key[:16], key[16:]

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
    aes_key, hmac_key = make_keys(password, iterations=ITERATIONS)
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
    salt = SALT

    aes_key, hmac_key = make_keys(password, salt, iterations=ITERATIONS)
    hmac = make_hmac(ciphertext, hmac_key)
    if hmac != data["hmac"]:
        print("HMAC doesn't match. Either the password was wrong, or the message was altered")
        raise ValueError
    output_data = decrypt(ciphertext, aes_key, iv)
    return output_data
