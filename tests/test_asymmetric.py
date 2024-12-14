# tests/test_asymmetric.py
import unittest
from library.asymmetric import generate_rsa_keys, rsa_encrypt, rsa_decrypt

class TestAsymmetric(unittest.TestCase):
    def test_rsa_encrypt_decrypt(self):
        private_key, public_key = generate_rsa_keys()
        data = b"confidential data"
        encrypted = rsa_encrypt(data, public_key)
        decrypted = rsa_decrypt(encrypted, private_key)
        self.assertEqual(decrypted, data)

    def test_invalid_decryption(self):
        private_key, public_key = generate_rsa_keys()
        _, wrong_private_key = generate_rsa_keys()
        data = b"confidential data"
        encrypted = rsa_encrypt(data, public_key)
        with self.assertRaises(ValueError):  # Decryption with wrong key should fail
            rsa_decrypt(encrypted, wrong_private_key)

if __name__ == "__main__":
    unittest.main()
