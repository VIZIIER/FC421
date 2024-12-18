# FC421

**FC421** is a Python-based project developed as part of the **Applied Cryptography** course at **Prince Mugrin University**. The project, created by Sultan, implements various cryptographic operations, including modules for asymmetric encryption, secure channels, digital signatures, and symmetric encryption.

## Features

- **Asymmetric Encryption**: Implementations for public and private key encryption.
- **Secure Channels**: Establishment of encrypted communication channels.
- **Digital Signatures**: Creation and verification of digital signatures.
- **Symmetric Encryption**: Functions for symmetric key encryption and decryption.

## Installation

1. **Clone the repository**:
   ```
   git clone https://github.com/VIZIIER/FC421.git
   ```
   
2. **Navigate to the project directory**:
   ```
   cd
   ```

3. **Install the required dependencies**:
```
pip install -r requirements.txt
```

## Usage 
1. **Import the desired module**:
```
from library import asymmetric, secure_channel, signatures, symmetric
```
2. **Example**: Encrypting a message using asymmetric encryption:
```
   # Generate keys
private_key, public_key = asymmetric.generate_keys()

# Encrypt a message
encrypted_message = asymmetric.encrypt(public_key, b'Your message here')

# Decrypt the message
decrypted_message = asymmetric.decrypt(private_key, encrypted_message)
```

## Testing
to run the test:
```
python -m unittest discover tests
```
