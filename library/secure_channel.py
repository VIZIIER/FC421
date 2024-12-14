# secure_channel.py
from Crypto.Random import get_random_bytes
from .symmetric import aes_encrypt, aes_decrypt
from .asymmetric import rsa_encrypt, rsa_decrypt

def secure_channel_exchange(public_key: bytes) -> bytes:
    """
    Securely exchange a symmetric key using RSA public key.
    :param public_key: Public key of the recipient.
    :return: Encrypted symmetric key.
    """
    symmetric_key = get_random_bytes(16)  # Generate a 128-bit AES key
    encrypted_key = rsa_encrypt(symmetric_key, public_key)
    return encrypted_key

def secure_channel_communicate(encrypted_key: bytes, private_key: bytes, message: bytes) -> dict:
    """
    Encrypt and send a message securely.
    :param encrypted_key: Encrypted symmetric key.
    :param private_key: RSA private key to decrypt the symmetric key.
    :param message: Message to encrypt.
    :return: Encrypted message (AES encrypted).
    """
    symmetric_key = rsa_decrypt(encrypted_key, private_key)
    return aes_encrypt(message, symmetric_key)

def secure_channel_receive(encrypted_data: dict, encrypted_key: bytes, private_key: bytes) -> bytes:
    """
    Decrypt a message received over a secure channel.
    :param encrypted_data: AES encrypted message with metadata (nonce, tag, ciphertext).
    :param encrypted_key: Encrypted symmetric key.
    :param private_key: RSA private key to decrypt the symmetric key.
    :return: Decrypted message.
    """
    symmetric_key = rsa_decrypt(encrypted_key, private_key)
    return aes_decrypt(encrypted_data, symmetric_key)
