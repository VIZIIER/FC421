# hashing.py
import hashlib

def sha256_hash(data: bytes) -> str:
    """Generate a SHA-256 hash."""
    return hashlib.sha256(data).hexdigest()

def sha3_256_hash(data: bytes) -> str:
    """Generate a SHA-3-256 hash."""
    return hashlib.sha3_256(data).hexdigest()

def verify_hash(data: bytes, hash_value: str, algorithm="sha256") -> bool:
    """
    Verify if the hash of the data matches the given hash value.
    :param data: Data to hash.
    :param hash_value: Expected hash.
    :param algorithm: Hash algorithm ('sha256' or 'sha3-256').
    """
    if algorithm == "sha256":
        return sha256_hash(data) == hash_value
    elif algorithm == "sha3-256":
        return sha3_256_hash(data) == hash_value
    else:
        raise ValueError("Unsupported algorithm. Use 'sha256' or 'sha3-256'.")
