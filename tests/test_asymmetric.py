# tests/test_asymmetric.py
import unittest
from library.asymmetric import generate_rsa_keys, rsa_encrypt, rsa_decrypt
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

class TestAsymmetric(unittest.TestCase):
    def test_rsa_encrypt_decrypt(self):
        private_key, public_key = generate_rsa_keys()
        data = b"confidential data"
        encrypted = rsa_encrypt(data, public_key)
        decrypted = rsa_decrypt(encrypted, private_key)
        self.assertEqual(decrypted, data)

    def test_invalid_decryption(self):
        # Generate two separate RSA key pairs
        private_key, public_key = generate_rsa_keys()
        wrong_private_key, _ = generate_rsa_keys()  # A completely different private key

        # Encrypt data using the correct public key
        data = b"confidential data"
        encrypted = rsa_encrypt(data, public_key)

        # Attempt decryption with the wrong private key and assert failure
        with self.assertRaises(ValueError):  # PKCS1_OAEP raises ValueError for mismatches
            cipher = PKCS1_OAEP.new(RSA.import_key(wrong_private_key))
            cipher.decrypt(encrypted)

if __name__ == "__main__":
    unittest.main()
