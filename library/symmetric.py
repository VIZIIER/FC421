# symmetric.py
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import base64

def aes_encrypt(data: bytes, key: bytes) -> dict:
    """
    Encrypt data using AES (GCM mode).
    :param data: Data to encrypt.
    :param key: Symmetric key (16/24/32 bytes for AES).
    :return: Dictionary containing ciphertext, tag, and nonce.
    """
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return {
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8'),
        "nonce": base64.b64encode(cipher.nonce).decode('utf-8'),
    }

def aes_decrypt(encrypted_data: dict, key: bytes) -> bytes:
    """
    Decrypt AES encrypted data.
    :param encrypted_data: Dictionary with ciphertext, tag, and nonce.
    :param key: Symmetric key.
    :return: Decrypted data.
    """
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])
    tag = base64.b64decode(encrypted_data['tag'])
    nonce = base64.b64decode(encrypted_data['nonce'])
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
