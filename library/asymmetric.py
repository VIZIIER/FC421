# asymmetric.py
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

def generate_rsa_keys(key_size=2048):
    """
    Generate RSA public and private keys.
    :param key_size: Key size in bits (default 2048).
    :return: Private key and public key as bytes.
    """
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(data: bytes, public_key: bytes) -> bytes:
    """Encrypt data using RSA public key."""
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(data)

def rsa_decrypt(encrypted_data: bytes, private_key: bytes) -> bytes:
    """Decrypt data using RSA private key."""
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(encrypted_data)
