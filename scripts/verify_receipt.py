"""Verify transcript lines and session receipt signatures.

Usage:
  # For server-side transcript (messages from client, receipt from server):
  py scripts/verify_receipt.py --transcript transcripts/transcript_<id>.txt \
      --receipt transcripts/receipt_<id>_server.json --cert certs/server_cert.pem \
      --message-cert certs/client_cert.pem
  
  # For client-side transcript (messages from client, receipt from client):
  py scripts/verify_receipt.py --transcript transcripts/transcript_<id>.txt \
      --receipt transcripts/receipt_<id>_client.json --cert certs/client_cert.pem
"""

import argparse
import json
import sys
from pathlib import Path

# Add project root to path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from app.common.utils import b64d, sha256_hex
from app.crypto.sign import verify as rsa_verify


def load_cert(cert_path: str):
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())


def verify_transcript_messages(transcript_path: str, public_key) -> bool:
    """
    Verify each transcript line signature: h = SHA256(seqno||ts||ct).
    Line format: seqno|ts|ct|sig|fingerprint
    """
    ok = True
    with open(transcript_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                seqno_str, ts_str, ct_b64, sig_b64, _fp = line.split("|", 4)
            except ValueError:
                print(f"[Line {idx}] Malformed line")
                ok = False
                continue
            ct = b64d(ct_b64)
            sig = b64d(sig_b64)

            data = (seqno_str.encode("utf-8")
                    + ts_str.encode("utf-8")
                    + ct)
            digest = hashes.Hash(hashes.SHA256())
            digest.update(data)
            hash_bytes = digest.finalize()

            if not rsa_verify(public_key, sig, hash_bytes):
                print(f"[Line {idx}] Signature verification FAILED")
                ok = False
    return ok


def verify_receipt(receipt_path: str, public_key, transcript_hash_hex: str, skip_hash_check: bool = False) -> bool:
    """
    Verify the receipt signature over the transcript hash (hex string).
    
    Args:
        receipt_path: Path to receipt JSON file
        public_key: Public key to verify signature
        transcript_hash_hex: Expected transcript hash (hex string)
        skip_hash_check: If True, verify signature over claimed hash even if it doesn't match expected
    """
    with open(receipt_path, "r", encoding="utf-8") as f:
        receipt = json.load(f)
    claimed_hex = receipt.get("transcript_sha256")
    if not skip_hash_check and claimed_hex != transcript_hash_hex:
        print("Receipt transcript hash mismatch")
        return False
    sig_b64 = receipt.get("sig")
    if not sig_b64:
        print("Receipt missing signature")
        return False
    sig = b64d(sig_b64)
    # Sign/verify: sign() hashes the data, so verify() also hashes
    # Pass the raw bytes (hex string) to verify, it will hash internally
    msg = claimed_hex.encode("utf-8")
    return rsa_verify(public_key, sig, msg)


def recompute_transcript_hash(transcript_path: str) -> str:
    with open(transcript_path, "r", encoding="utf-8") as f:
        content = f.read().rstrip("\n")
    return sha256_hex(content.encode("utf-8"))


def main():
    ap = argparse.ArgumentParser(description="Verify transcript and receipt signatures")
    ap.add_argument("--transcript", required=True, help="Path to transcript file")
    ap.add_argument("--receipt", required=True, help="Path to receipt JSON")
    ap.add_argument("--cert", required=True, help="PEM certificate for receipt verification (signer of receipt)")
    ap.add_argument("--message-cert", help="PEM certificate for message verification (if different from receipt cert)")
    args = ap.parse_args()

    transcript_path = args.transcript
    receipt_path = args.receipt
    receipt_cert_path = args.cert
    message_cert_path = args.message_cert or receipt_cert_path

    # Load certificates
    receipt_cert = load_cert(receipt_cert_path)
    receipt_public_key = receipt_cert.public_key()
    
    message_cert = load_cert(message_cert_path)
    message_public_key = message_cert.public_key()

    print(f"Verifying messages in {transcript_path} using {message_cert_path}...")
    msgs_ok = verify_transcript_messages(transcript_path, message_public_key)
    print(f"Message signatures: {'OK' if msgs_ok else 'FAIL'}")

    print("Recomputing transcript hash ...")
    th = recompute_transcript_hash(transcript_path)
    print(f"Transcript SHA256: {th}")
    
    # Load receipt to show claimed hash
    with open(receipt_path, "r", encoding="utf-8") as f:
        receipt = json.load(f)
    claimed_hash = receipt.get("transcript_sha256", "")
    print(f"Receipt claims hash: {claimed_hash}")
    
    if claimed_hash != th:
        print(f"⚠️  WARNING: Hash mismatch! Receipt was signed for a different transcript state.")
        print(f"   This receipt may be from before messages were added, or the transcript was modified.")
        print(f"   Verifying receipt signature over its claimed hash...")
        # Verify signature over the claimed hash (what was actually signed)
        receipt_ok = verify_receipt(receipt_path, receipt_public_key, claimed_hash, skip_hash_check=True)
    else:
        print(f"Verifying receipt in {receipt_path} using {receipt_cert_path}...")
        receipt_ok = verify_receipt(receipt_path, receipt_public_key, th)
    print(f"Receipt signature: {'OK' if receipt_ok else 'FAIL'}")

    if msgs_ok and receipt_ok:
        print("All verifications succeeded.")
    else:
        print("One or more verifications failed.")


if __name__ == "__main__":
    main()

