# signatures.py
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

def sign_data(data: bytes, private_key: bytes) -> bytes:
    """
    Sign data using RSA private key.
    :param data: Data to be signed.
    :param private_key: Private key for signing.
    :return: Digital signature.
    """
    key = RSA.import_key(private_key)
    hash_obj = SHA256.new(data)
    return pkcs1_15.new(key).sign(hash_obj)

def verify_signature(data: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verify RSA digital signature.
    :param data: Original data.
    :param signature: Signature to verify.
    :param public_key: Public key to verify the signature.
    :return: True if the signature is valid, False otherwise.
    """
    key = RSA.import_key(public_key)
    hash_obj = SHA256.new(data)
    try:
        pkcs1_15.new(key).verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False
