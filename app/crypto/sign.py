"""RSA PKCS#1 v1.5 SHA-256 sign/verify."""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


def load_private_key(filepath: str) -> rsa.RSAPrivateKey:
    """
    Load RSA private key from PEM file.
    
    Args:
        filepath: path to private key file
        
    Returns:
        RSAPrivateKey object
    """
    with open(filepath, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())


def load_public_key_from_cert(cert_pem: str):
    """
    Extract RSA public key from certificate.
    
    Args:
        cert_pem: PEM-encoded certificate string
        
    Returns:
        RSAPublicKey object
    """
    from app.crypto.pki import load_certificate
    cert = load_certificate(cert_pem)
    return cert.public_key()


def sign(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """
    Sign data using RSA PKCS#1 v1.5 with SHA-256.
    
    Args:
        private_key: RSA private key
        data: data to sign
        
    Returns:
        signature bytes
    """
    return private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )


def verify(public_key, signature: bytes, data: bytes) -> bool:
    """
    Verify RSA signature.
    
    Args:
        public_key: RSA public key
        signature: signature bytes
        data: original data
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
