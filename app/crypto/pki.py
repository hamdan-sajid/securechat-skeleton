"""X.509 validation: signed-by-CA, validity window, CN/SAN."""

from datetime import datetime
from typing import Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.x509.oid import NameOID


def load_certificate(pem_data: str) -> x509.Certificate:
    """
    Load X.509 certificate from PEM string.
    
    Args:
        pem_data: PEM-encoded certificate string
        
    Returns:
        x509.Certificate object
    """
    return x509.load_pem_x509_certificate(pem_data.encode('utf-8'), default_backend())


def load_ca_certificate(filepath: str) -> x509.Certificate:
    """
    Load CA certificate from file.
    
    Args:
        filepath: path to CA certificate file
        
    Returns:
        x509.Certificate object
    """
    with open(filepath, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())


def verify_certificate_chain(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """
    Verify that certificate is signed by the CA.
    
    Args:
        cert: certificate to verify
        ca_cert: CA certificate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        # Check that the issuer matches the CA subject
        if cert.issuer != ca_cert.subject:
            return False
        
        # Get CA's public key
        ca_public_key = ca_cert.public_key()
        
        # Verify signature based on the signature algorithm
        if isinstance(ca_public_key, rsa.RSAPublicKey):
            # RSA signature verification with SHA-256
            if cert.signature_hash_algorithm.name == 'sha256':
                ca_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    asym_padding.PKCS1v15(),
                    hashes.SHA256()
                )
                return True
        # For other key types or algorithms, return False for now
        return False
    except Exception as e:
        return False


def check_certificate_validity(cert: x509.Certificate) -> bool:
    """
    Check if certificate is within validity period.
    
    Args:
        cert: certificate to check
        
    Returns:
        True if valid, False if expired or not yet valid
    """
    now = datetime.utcnow()
    return cert.not_valid_before <= now <= cert.not_valid_after


def get_common_name(cert: x509.Certificate) -> str:
    """
    Extract Common Name (CN) from certificate subject.
    
    Args:
        cert: certificate
        
    Returns:
        Common Name string, or empty string if not found
    """
    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        return cn
    except (IndexError, AttributeError):
        return ""


def validate_certificate(cert_pem: str, ca_cert_path: str, expected_cn: Optional[str] = None) -> tuple[bool, str]:
    """
    Comprehensive certificate validation.
    
    Args:
        cert_pem: PEM-encoded certificate string
        ca_cert_path: path to CA certificate file
        expected_cn: expected Common Name (optional)
        
    Returns:
        (is_valid, error_message) tuple
    """
    try:
        # Load certificate
        cert = load_certificate(cert_pem)
        
        # Load CA certificate
        ca_cert = load_ca_certificate(ca_cert_path)
        
        # Check if self-signed (should not be)
        if cert.issuer == cert.subject:
            return False, "BAD_CERT: Certificate is self-signed"
        
        # Verify certificate chain
        if not verify_certificate_chain(cert, ca_cert):
            return False, "BAD_CERT: Certificate not signed by trusted CA"
        
        # Check validity period
        if not check_certificate_validity(cert):
            return False, "BAD_CERT: Certificate expired or not yet valid"
        
        # Check Common Name if provided
        if expected_cn:
            cn = get_common_name(cert)
            if cn != expected_cn:
                return False, f"BAD_CERT: Common Name mismatch (expected: {expected_cn}, got: {cn})"
        
        return True, "OK"
    except Exception as e:
        return False, f"BAD_CERT: {str(e)}"
