"""
# @FILE         encryptString.py
# @AUTHOR       doorJH
# @DATE         2023.09.07
# @MODIFIED
# @VERSION      1.0.0
# @DESCRIPTION String에서  MD5 / AES / RSA / SHA  암호화, 복호화
"""

import hashlib
import crypto
import sys
sys.modules['Crypto'] = crypto
from crypto.Cipher import AES
from crypto.Random import get_random_bytes
from crypto.Protocol.KDF import scrypt
from crypto.Cipher import AES
from crypto.Random import get_random_bytes
from crypto.Protocol.KDF import scrypt

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa


def md5_encrypt(text):
    md5_hash = hashlib.md5()
    md5_hash.update(text.encode())
    return md5_hash.hexdigest()



def sha224_encrypt(text):
    sha_hash = hashlib.sha224()
    sha_hash.update(text.encode())
    return sha_hash.hexdigest()

def sha256_encrypt(text):
    sha_hash = hashlib.sha256()
    sha_hash.update(text.encode())
    return sha_hash.hexdigest()

def sha512_encrypt(text):
    sha_hash = hashlib.sha512()
    sha_hash.update(text.encode())
    return sha_hash.hexdigest()



def aes_encrypt(text, password):
    salt = get_random_bytes(16)
    key = scrypt(password, salt, 32, N=2**14, r=8, p=1)
    cipher = AES.new(key, AES.MODE_GCM)

    cipher_text, tag = cipher.encrypt_and_digest(text.encode())

    return salt +  tag + cipher_text

def aes_decrypt(encrypted_text, password):
    salt = encrypted_text[:16]
    tag = encrypted_text[16:32]
    cipher_text = encrypted_text[32:]

    key = scrypt(password, salt, 32, N=2**14, r=8, p=1)

    cipher = AES.new(key, AES.MODE_GCM, nonce=salt)
    plain_text = cipher.decrypt_and_verify(cipher_text, tag)

    return plain_text.decode()



def generate_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_pem, public_key_pem

def rsa_encrypt(text, public_key):
    public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
    cipher_text = public_key.encrypt(
        text.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cipher_text.hex()

def rsa_decrypt(encrypted_text, private_key):
    private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
    plain_text = private_key.decrypt(
        bytes.fromhex(encrypted_text),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plain_text.decode()
