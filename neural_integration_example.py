#!/usr/bin/env python3
# 🧠🔒 CortexCrypto Neural Integration Example

from neural_crypto_integration import NeuralKeyAugmenter
import os

def encrypt_with_neural_augmentation(data: bytes, password: str, environment: str) -> bytes:
    """Encrypt data using neural-augmented keys"""
    # Initialize neural augmenter
    augmenter = NeuralKeyAugmenter()

    # Create encryption components
    password_bytes = password.encode('utf-8')
    binding_bytes = environment.encode('utf-8')
    session_salt = os.urandom(16)

    # Derive neural-augmented key
    augmented_key, used_neural = augmenter.derive_augmented_key(
        password_bytes, binding_bytes, session_salt
    )

    neural_flag = 'NEURAL' if used_neural else 'CRYPTO'
    print(f'🔑 Key derivation: {neural_flag} | Key: {augmented_key[:8].hex()}...')

    # Here you would use augmented_key with your encryption algorithm
    # This is just a demo - use proper AES/ChaCha20 in production!
    encrypted = bytearray()
    for i, byte in enumerate(data):
        encrypted.append(byte ^ augmented_key[i % len(augmented_key)])

    return session_salt + bytes(encrypted)

# Example usage
if __name__ == '__main__':
    test_data = b'This is secret neural-crypto data!'
    encrypted = encrypt_with_neural_augmentation(test_data, 'my_password', 'laptop')
    print(f'🔒 Encrypted: {encrypted[:16].hex()}...')
