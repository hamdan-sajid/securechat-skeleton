"""Append-only transcript + TranscriptHash helpers."""

import os
import hashlib
from typing import List, Tuple
from app.common.utils import sha256_hex


class Transcript:
    """Append-only transcript for session messages."""
    
    def __init__(self, session_id: str, peer_cert_fingerprint: str):
        """
        Initialize transcript.
        
        Args:
            session_id: unique session identifier
            peer_cert_fingerprint: fingerprint of peer's certificate
        """
        self.session_id = session_id
        self.peer_cert_fingerprint = peer_cert_fingerprint
        self.entries: List[Tuple[int, int, str, str]] = []  # (seqno, ts, ct, sig)
        self.transcript_dir = "transcripts"
        os.makedirs(self.transcript_dir, exist_ok=True)
    
    def add_message(self, seqno: int, timestamp: int, ciphertext: str, signature: str):
        """
        Add a message entry to the transcript.
        
        Args:
            seqno: sequence number
            timestamp: unix timestamp in milliseconds
            ciphertext: base64-encoded ciphertext
            signature: base64-encoded signature
        """
        self.entries.append((seqno, timestamp, ciphertext, signature))
    
    def get_transcript_lines(self) -> List[str]:
        """
        Get all transcript lines in format: seqno|ts|ct|sig|peer-cert-fingerprint
        
        Returns:
            List of transcript line strings
        """
        lines = []
        for seqno, ts, ct, sig in self.entries:
            line = f"{seqno}|{ts}|{ct}|{sig}|{self.peer_cert_fingerprint}"
            lines.append(line)
        return lines
    
    def compute_transcript_hash(self) -> str:
        """
        Compute SHA-256 hash of concatenated transcript lines.
        
        Returns:
            hex-encoded transcript hash
        """
        lines = self.get_transcript_lines()
        concatenated = "\n".join(lines)
        return sha256_hex(concatenated.encode('utf-8'))
    
    def save_to_file(self):
        """Save transcript to file."""
        filename = os.path.join(self.transcript_dir, f"transcript_{self.session_id}.txt")
        with open(filename, 'w') as f:
            for line in self.get_transcript_lines():
                f.write(line + "\n")
        print(f"Transcript saved to {filename}")
    
    def get_first_seq(self) -> int:
        """Get first sequence number."""
        if not self.entries:
            return 0
        return self.entries[0][0]
    
    def get_last_seq(self) -> int:
        """Get last sequence number."""
        if not self.entries:
            return 0
        return self.entries[-1][0]


def get_certificate_fingerprint(cert_pem: str) -> str:
    """
    Compute SHA-256 fingerprint of certificate.
    
    Args:
        cert_pem: PEM-encoded certificate string
        
    Returns:
        hex-encoded fingerprint
    """
    from app.crypto.pki import load_certificate
    from cryptography.hazmat.primitives import hashes
    cert = load_certificate(cert_pem)
    fingerprint = cert.fingerprint(hashes.SHA256())
    return fingerprint.hex()
