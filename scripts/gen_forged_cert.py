"""Generate a forged certificate for testing - claims to be signed by CA but isn't."""

import argparse
import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID


def load_ca_cert(ca_cert_path: str):
    """Load CA certificate to copy issuer name."""
    with open(ca_cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())


def generate_forged_certificate(cn: str, ca_cert_path: str, output_prefix: str, output_dir: str = "certs"):
    """
    Generate a forged certificate that claims to be signed by CA but is actually self-signed.
    
    This certificate will:
    - Have the CA's name as issuer (looks legitimate)
    - But be signed by its own private key (not by CA)
    - Will fail validation with: "Certificate not signed by trusted CA"
    
    Args:
        cn: Common Name for the certificate
        ca_cert_path: path to CA certificate (to copy issuer name)
        output_prefix: prefix for output files (e.g., "forged_client")
        output_dir: directory to save certificates
    """
    os.makedirs(output_dir, exist_ok=True)
    
    # Load CA certificate to get issuer name
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
    
    # FORGED: Use CA's issuer name, but sign with our own key (not CA's key)
    # This makes it look like it came from the CA, but the signature won't verify
    issuer = ca_cert.subject  # Copy CA's subject as issuer (makes it look legitimate)
    
    # Build certificate - signed by our own key, not CA's key
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer  # Claims to be issued by CA
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)  # 1 year
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
    ).sign(private_key, hashes.SHA256(), default_backend())  # ⚠️ Signed by our key, not CA!
    
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
    print(f"Forged certificate saved to {cert_path}")
    
    print(f"\n⚠️  FORGED certificate for '{cn}' generated!")
    print(f"   This certificate claims to be issued by the CA but is actually self-signed.")
    print(f"   It will fail validation with: 'Certificate not signed by trusted CA'")
    print(f"Certificate valid from {cert.not_valid_before} to {cert.not_valid_after}")
    print(f"\nTo test, update .env:")
    print(f"  CLIENT_CERT_PATH={cert_path}")
    print(f"  CLIENT_KEY_PATH={key_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate forged certificate for testing")
    parser.add_argument("--cn", required=True, help="Common Name (e.g., forged.client.local)")
    parser.add_argument("--ca-cert", default="certs/ca_cert.pem", help="CA certificate path (to copy issuer name)")
    parser.add_argument("--out", required=True, help="Output prefix (e.g., forged_client)")
    parser.add_argument("--dir", default="certs", help="Output directory")
    args = parser.parse_args()
    
    generate_forged_certificate(args.cn, args.ca_cert, args.out, args.dir)

