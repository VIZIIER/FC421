# tests/test_symmetric.py
import unittest
from library.symmetric import aes_encrypt, aes_decrypt
from Cryptodome.Random import get_random_bytes

class TestSymmetric(unittest.TestCase):
    def test_aes_encrypt_decrypt(self):
        data = b"secret message"
        key = get_random_bytes(16)  # AES-128
        encrypted = aes_encrypt(data, key)
        decrypted = aes_decrypt(encrypted, key)
        self.assertEqual(decrypted, data)

    def test_invalid_key(self):
        data = b"secret message"
        key = get_random_bytes(16)
        wrong_key = get_random_bytes(16)
        encrypted = aes_encrypt(data, key)
        with self.assertRaises(ValueError):  # Should fail decryption
            aes_decrypt(encrypted, wrong_key)

if __name__ == "__main__":
    unittest.main()
