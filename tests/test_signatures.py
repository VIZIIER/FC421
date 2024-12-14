# tests/test_signatures.py
import unittest
from library.signatures import sign_data, verify_signature
from library.asymmetric import generate_rsa_keys

class TestSignatures(unittest.TestCase):
    def test_sign_and_verify(self):
        private_key, public_key = generate_rsa_keys()
        data = b"important message"
        signature = sign_data(data, private_key)
        self.assertTrue(verify_signature(data, signature, public_key))

    def test_invalid_signature(self):
        private_key, public_key = generate_rsa_keys()
        _, wrong_public_key = generate_rsa_keys()
        data = b"important message"
        signature = sign_data(data, private_key)
        self.assertFalse(verify_signature(data, signature, wrong_public_key))

if __name__ == "__main__":
    unittest.main()
