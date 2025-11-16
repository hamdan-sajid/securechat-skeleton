"""AES-128(ECB)+PKCS#7 helpers (use library)."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext using AES-128-ECB with PKCS#7 padding.
    
    Args:
        key: 16-byte AES key
        plaintext: data to encrypt
        
    Returns:
        ciphertext bytes
    """
    if len(key) != 16:
        raise ValueError("AES key must be exactly 16 bytes")
    
    # Apply PKCS#7 padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    # Encrypt with AES-128-ECB
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return ciphertext


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-128-ECB and remove PKCS#7 padding.
    
    Args:
        key: 16-byte AES key
        ciphertext: encrypted data
        
    Returns:
        plaintext bytes
    """
    if len(key) != 16:
        raise ValueError("AES key must be exactly 16 bytes")
    
    # Decrypt with AES-128-ECB
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS#7 padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    
    return plaintext
