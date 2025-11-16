"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""

import hashlib
import secrets
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend


# Standard DH parameters (RFC 3526, 2048-bit MODP Group)
# Using smaller parameters for practical testing
DEFAULT_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA015015950EAC3E3AA62E0C
DEFAULT_G = 2


def generate_private_key() -> int:
    """Generate a random private key for DH."""
    return secrets.randbelow(DEFAULT_P - 2) + 1


def compute_public_value(private_key: int, g: int, p: int) -> int:
    """
    Compute public value: public = g^private mod p.
    
    Args:
        private_key: private exponent
        g: generator
        p: prime modulus
        
    Returns:
        public value (g^private mod p)
    """
    return pow(g, private_key, p)


def derive_shared_secret(private_key: int, peer_public: int, p: int) -> int:
    """
    Derive shared secret: Ks = peer_public^private_key mod p.
    
    Args:
        private_key: our private exponent
        peer_public: peer's public value
        p: prime modulus
        
    Returns:
        shared secret Ks
    """
    return pow(peer_public, private_key, p)


def derive_aes_key(shared_secret: int) -> bytes:
    """
    Derive AES-128 key from shared secret: K = Trunc16(SHA256(big-endian(Ks))).
    
    Args:
        shared_secret: the shared secret Ks from DH
        
    Returns:
        16-byte AES key
    """
    # Convert shared secret to big-endian bytes
    # Calculate minimum bytes needed
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')
    
    # Compute SHA-256 hash
    hash_bytes = hashlib.sha256(secret_bytes).digest()
    
    # Truncate to 16 bytes (first 16 bytes)
    return hash_bytes[:16]
