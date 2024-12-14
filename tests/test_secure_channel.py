# tests/test_secure_channel.py
import unittest
from library.secure_channel import secure_channel_exchange, secure_channel_communicate, secure_channel_receive
from library.asymmetric import generate_rsa_keys


class TestSecureChannel(unittest.TestCase):
    def test_secure_channel(self):
        private_key, public_key = generate_rsa_keys()
        message = b"secure message"

        # Simulate key exchange
        encrypted_key = secure_channel_exchange(public_key)

        # Simulate secure communication
        encrypted_message = secure_channel_communicate(encrypted_key, private_key, message)
        decrypted_message = secure_channel_receive(encrypted_message, encrypted_key, private_key)
        self.assertEqual(decrypted_message, message)


if __name__ == "__main__":
    unittest.main()
