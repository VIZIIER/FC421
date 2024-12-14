# tests/test_pki.py
import unittest
from library.pki import create_self_signed_cert

class TestPKI(unittest.TestCase):
    def test_create_self_signed_cert(self):
        cert, private_key = create_self_signed_cert("test.com")
        self.assertIn(b"BEGIN CERTIFICATE", cert)
        self.assertIn(b"BEGIN PRIVATE KEY", private_key)

if __name__ == "__main__":
    unittest.main()
