# tests/test_hashing.py
import unittest
from library.hashing import sha256_hash, sha3_256_hash, verify_hash

class TestHashing(unittest.TestCase):
    def test_sha256_hash(self):
        data = b"test"
        expected_hash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        self.assertEqual(sha256_hash(data), expected_hash)

    def test_sha3_256_hash(self):
        data = b"test"
        # Corrected expected hash for SHA3-256 of "test"
        expected_hash = "36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80"
        self.assertEqual(sha3_256_hash(data), expected_hash)

    def test_verify_hash(self):
        data = b"test"
        valid_hash = sha256_hash(data)
        self.assertTrue(verify_hash(data, valid_hash, "sha256"))
        self.assertFalse(verify_hash(data, "invalid_hash", "sha256"))

if __name__ == "__main__":
    unittest.main()
