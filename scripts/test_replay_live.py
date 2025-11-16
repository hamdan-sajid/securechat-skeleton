"""Live replay test - resend old message to trigger REPLAY detection."""

import socket
import json
import secrets
import hashlib
import sys
import os
from pathlib import Path

# Add project root to path (scripts folder is one level down)
script_dir = Path(__file__).resolve().parent
project_root = script_dir.parent
sys.path.insert(0, str(project_root))

# Change to project root directory for relative paths to work
os.chdir(project_root)

from app.common.utils import now_ms, b64e, b64d
from app.crypto.aes import encrypt, decrypt
from app.crypto.dh import generate_private_key, compute_public_value, derive_shared_secret, derive_aes_key, DEFAULT_P, DEFAULT_G
from app.crypto.pki import validate_certificate
from app.crypto.sign import load_private_key, load_public_key_from_cert, sign
from dotenv import load_dotenv

load_dotenv()


class ReplayTestClient:
    """Client that sends a replayed message to test REPLAY detection."""
    
    def __init__(self):
        self.host = "localhost"
        self.port = 8888
        self.ca_cert_path = os.getenv("CA_CERT_PATH", "certs/ca_cert.pem")
        self.client_cert_path = os.getenv("CLIENT_CERT_PATH", "certs/client_cert.pem")
        self.client_key_path = os.getenv("CLIENT_KEY_PATH", "certs/client_key.pem")
        self.client_cert_pem = self._load_cert_pem()
        self.client_private_key = load_private_key(self.client_key_path)
        self.expected_server_cn = os.getenv("SERVER_CN", "server.local")
        self.sock = None
        self.session_key = None
        self.seqno = 0
    
    def _load_cert_pem(self) -> str:
        with open(self.client_cert_path, 'r') as f:
            return f.read()
    
    def _send_message(self, message: dict):
        data = json.dumps(message) + "\n"
        self.sock.sendall(data.encode('utf-8'))
    
    def _receive_message(self) -> dict:
        buffer = b""
        while b"\n" not in buffer:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed")
            buffer += chunk
        line = buffer.split(b"\n", 1)[0]
        return json.loads(line.decode('utf-8'))
    
    def _exchange_certificates(self) -> str:
        """Exchange certificates."""
        client_nonce = secrets.token_bytes(16)
        hello = {
            "type": "hello",
            "client_cert": self.client_cert_pem,
            "nonce": b64e(client_nonce)
        }
        self._send_message(hello)
        
        msg = self._receive_message()
        if msg.get("type") == "error":
            print(f"Certificate rejected: {msg.get('message')}")
            return None
        if msg.get("type") != "server_hello":
            print(f"Error: Expected server_hello, got {msg.get('type')}")
            return None
        
        # Validate server certificate
        is_valid, error = validate_certificate(
            msg["server_cert"],
            self.ca_cert_path,
            self.expected_server_cn
        )
        if not is_valid:
            print(f"Server certificate invalid: {error}")
            return None
        
        return msg["server_cert"]
    
    def _perform_dh_exchange(self) -> bytes:
        """Perform DH key exchange."""
        client_private = generate_private_key()
        client_public = compute_public_value(client_private, DEFAULT_G, DEFAULT_P)
        
        self._send_message({
            "type": "dh_client",
            "g": DEFAULT_G,
            "p": DEFAULT_P,
            "A": client_public
        })
        
        msg = self._receive_message()
        if msg.get("type") != "dh_server":
            print(f"Error: Expected dh_server, got {msg.get('type')}")
            return None
        
        shared_secret = derive_shared_secret(client_private, msg["B"], DEFAULT_P)
        return derive_aes_key(shared_secret)
    
    def _login(self, email: str, password: str, aes_key: bytes) -> bool:
        """Login with credentials."""
        login_data = {
            "type": "login",
            "email": email,
            "pwd": password,
            "nonce": b64e(secrets.token_bytes(16))
        }
        
        data_json = json.dumps(login_data).encode('utf-8')
        encrypted_data = encrypt(aes_key, data_json)
        
        self._send_message({
            "type": "login",
            "encrypted_data": b64e(encrypted_data)
        })
        
        msg = self._receive_message()
        if msg.get("type") == "login_success":
            print("Login successful")
            return True
        else:
            print(f"Login failed: {msg.get('message')}")
            return False
    
    def _send_chat_message(self, plaintext: str, server_cert: str) -> dict:
        """Send a chat message and return it for replay."""
        self.seqno += 1
        
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext = encrypt(self.session_key, plaintext_bytes)
        ciphertext_b64 = b64e(ciphertext)
        
        timestamp = now_ms()
        
        # Compute hash and sign
        seqno_bytes = str(self.seqno).encode('utf-8')
        ts_bytes = str(timestamp).encode('utf-8')
        ct_bytes = ciphertext
        hash_input = seqno_bytes + ts_bytes + ct_bytes
        hash_bytes = hashlib.sha256(hash_input).digest()
        
        signature = sign(self.client_private_key, hash_bytes)
        signature_b64 = b64e(signature)
        
        msg = {
            "type": "msg",
            "seqno": self.seqno,
            "ts": timestamp,
            "ct": ciphertext_b64,
            "sig": signature_b64
        }
        
        self._send_message(msg)
        response = self._receive_message()
        print(f"Message response: {response}")
        return msg
    
    def _replay_message(self, original_msg: dict):
        """Resend the exact same message (replay attack)."""
        print("\n" + "="*60)
        print("REPLAYING MESSAGE (Exact same message with same seqno)")
        print("="*60)
        
        print(f"Replaying message with seqno: {original_msg['seqno']}")
        print(f"Original timestamp: {original_msg['ts']}")
        print(f"Ciphertext: {original_msg['ct'][:30]}...")
        print(f"Signature: {original_msg['sig'][:30]}...")
        print("\n⚠️  This is a REPLAY ATTACK - sending exact same message again")
        
        # Send the EXACT same message (no modifications)
        self._send_message(original_msg)
        response = self._receive_message()
        
        print(f"\nServer response: {response}")
        if response.get("type") == "error" and response.get("message") == "REPLAY":
            print("\n✅ SUCCESS: Server correctly detected replay attack (REPLAY)")
            print("   The server rejected the message because seqno was already used.")
        else:
            print(f"\n❌ Unexpected response: {response}")
            print("   Expected: {'type': 'error', 'message': 'REPLAY'}")
    
    def run_replay_test(self, email: str, password: str):
        """Run the complete replay test."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            print(f"Connected to {self.host}:{self.port}")
            
            # Phase 1: Certificate exchange
            print("\n[1] Exchanging certificates...")
            server_cert = self._exchange_certificates()
            if not server_cert:
                return
            
            # Phase 2: Temporary DH for login
            print("[2] Performing DH exchange for login...")
            temp_aes_key = self._perform_dh_exchange()
            if not temp_aes_key:
                return
            
            # Phase 3: Login
            print("[3] Logging in...")
            if not self._login(email, password, temp_aes_key):
                return
            
            # Phase 4: Session key establishment
            print("[4] Establishing session key...")
            self.session_key = self._perform_dh_exchange()
            if not self.session_key:
                return
            
            print("\n✅ Session established!")
            
            # Phase 5: Send valid message
            print("\n[5] Sending valid message...")
            valid_msg = self._send_chat_message("Hello, this is a valid message", server_cert)
            
            # Phase 6: Replay the same message
            print("\n[6] Replaying the same message (replay attack)...")
            self._replay_message(valid_msg)
            
        except Exception as e:
            print(f"Error: {str(e)}")
            import traceback
            traceback.print_exc()
        finally:
            if self.sock:
                self.sock.close()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python scripts/test_replay_live.py <email> <password>")
        print("Example: python scripts/test_replay_live.py user@example.com mypassword")
        sys.exit(1)
    
    email = sys.argv[1]
    password = sys.argv[2]
    
    client = ReplayTestClient()
    client.run_replay_test(email, password)

