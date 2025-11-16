"""Generate an expired certificate for testing certificate validation."""

import argparse
import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID


def load_ca_key(ca_key_path: str):
    """Load CA private key."""
    with open(ca_key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())


def load_ca_cert(ca_cert_path: str):
    """Load CA certificate."""
    with open(ca_cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())


def generate_expired_certificate(cn: str, ca_key_path: str, ca_cert_path: str, output_prefix: str, output_dir: str = "certs", days_expired: int = 1):
    """
    Generate an expired certificate signed by the CA.
    
    Args:
        cn: Common Name for the certificate
        ca_key_path: path to CA private key
        ca_cert_path: path to CA certificate
        output_prefix: prefix for output files (e.g., "expired_client")
        output_dir: directory to save certificates
        days_expired: how many days ago the certificate expired
    """
    os.makedirs(output_dir, exist_ok=True)
    
    # Load CA key and certificate
    ca_key = load_ca_key(ca_key_path)
    ca_cert = load_ca_cert(ca_cert_path)
    
    # Generate RSA private key (2048 bits)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create certificate request
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    
    # Calculate dates: expired X days ago
    now = datetime.utcnow()
    not_valid_before = now - timedelta(days=365)  # Valid from 1 year ago
    not_valid_after = now - timedelta(days=days_expired)  # Expired X days ago
    
    # Build certificate
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        not_valid_before
    ).not_valid_after(
        not_valid_after  # Expired!
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(cn),
        ]),
        critical=False,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_agreement=False,
            content_commitment=False,
            data_encipherment=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=False,
            crl_sign=False
        ),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([
            x509.ExtendedKeyUsageOID.CLIENT_AUTH,
            x509.ExtendedKeyUsageOID.SERVER_AUTH,
        ]),
        critical=False,
    ).sign(ca_key, hashes.SHA256(), default_backend())
    
    # Save private key
    key_path = os.path.join(output_dir, f"{output_prefix}_key.pem")
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"Private key saved to {key_path}")
    
    # Save certificate
    cert_path = os.path.join(output_dir, f"{output_prefix}_cert.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Expired certificate saved to {cert_path}")
    
    print(f"\nExpired certificate for '{cn}' generated successfully!")
    print(f"Certificate valid from {cert.not_valid_before} to {cert.not_valid_after}")
    print(f"Certificate expired {days_expired} day(s) ago")
    print(f"\nTo test, update .env:")
    print(f"  CLIENT_CERT_PATH={cert_path}")
    print(f"  CLIENT_KEY_PATH={key_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate expired certificate for testing")
    parser.add_argument("--cn", required=True, help="Common Name (e.g., expired.client.local)")
    parser.add_argument("--ca-key", default="certs/ca_key.pem", help="CA private key path")
    parser.add_argument("--ca-cert", default="certs/ca_cert.pem", help="CA certificate path")
    parser.add_argument("--out", required=True, help="Output prefix (e.g., expired_client)")
    parser.add_argument("--dir", default="certs", help="Output directory")
    parser.add_argument("--days-expired", type=int, default=1, help="How many days ago the cert expired (default: 1)")
    args = parser.parse_args()
    
    generate_expired_certificate(args.cn, args.ca_key, args.ca_cert, args.out, args.dir, args.days_expired)

