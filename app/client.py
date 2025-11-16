"""Client skeleton — plain TCP; no TLS. See assignment spec."""

import os
import json
import socket
import secrets
import hashlib
import sys
from typing import Optional
from dotenv import load_dotenv

from app.common.protocol import (
    HelloMessage, ServerHelloMessage, RegisterMessage, LoginMessage,
    DHClientMessage, DHServerMessage, ChatMessage, SessionReceipt
)
from app.common.utils import now_ms, b64e, b64d, sha256_hex
from app.crypto.aes import encrypt, decrypt
from app.crypto.dh import generate_private_key, compute_public_value, derive_shared_secret, derive_aes_key, DEFAULT_P, DEFAULT_G
from app.crypto.pki import load_certificate, validate_certificate
from app.crypto.sign import load_private_key, load_public_key_from_cert, sign, verify
from app.storage.transcript import Transcript, get_certificate_fingerprint as get_fingerprint

load_dotenv()


class SecureChatClient:
    """Secure chat client implementing CIANR protocol."""
    
    def __init__(self, host: str = "localhost", port: int = 8888):
        self.host = host
        self.port = port
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
        """Load client certificate as PEM string."""
        with open(self.client_cert_path, 'r') as f:
            return f.read()
    
    def _send_message(self, message: dict):
        """Send JSON message over socket."""
        data = json.dumps(message) + "\n"
        self.sock.sendall(data.encode('utf-8'))
    
    def _receive_message(self) -> dict:
        """Receive JSON message from socket."""
        buffer = b""
        while b"\n" not in buffer:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed")
            buffer += chunk
        line = buffer.split(b"\n", 1)[0]
        return json.loads(line.decode('utf-8'))
    
    def _exchange_certificates(self) -> Optional[str]:
        """Exchange certificates with server."""
        # Send client hello
        client_nonce = secrets.token_bytes(16)
        hello = HelloMessage(
            client_cert=self.client_cert_pem,
            nonce=b64e(client_nonce)
        )
        self._send_message(hello.model_dump())
        
        # Receive server hello or error
        msg = self._receive_message()
        if msg.get("type") == "error":
            print(f"Certificate rejected by server: {msg.get('message', 'Unknown error')}")
            return None
        if msg.get("type") != "server_hello":
            print(f"Error: Expected server_hello, got {msg.get('type')}")
            return None
        
        server_hello = ServerHelloMessage(**msg)
        
        # Validate server certificate
        is_valid, error = validate_certificate(
            server_hello.server_cert,
            self.ca_cert_path,
            self.expected_server_cn
        )
        
        if not is_valid:
            print(f"Certificate validation failed: {error}")
            return None
        
        print("Certificate exchange successful")
        return server_hello.server_cert
    
    def _perform_dh_exchange(self, is_temporary: bool = False) -> Optional[bytes]:
        """Perform DH key exchange and return derived AES key."""
        # Generate client private key
        client_private = generate_private_key()
        
        # Compute client public value
        client_public = compute_public_value(client_private, DEFAULT_G, DEFAULT_P)
        
        # Send client DH parameters
        dh_client = DHClientMessage(g=DEFAULT_G, p=DEFAULT_P, A=client_public)
        self._send_message(dh_client.model_dump())
        
        # Receive server public value
        msg = self._receive_message()
        if msg.get("type") != "dh_server":
            print(f"Error: Expected dh_server, got {msg.get('type')}")
            return None
        
        dh_server = DHServerMessage(**msg)
        
        # Derive shared secret and AES key
        shared_secret = derive_shared_secret(client_private, dh_server.B, DEFAULT_P)
        aes_key = derive_aes_key(shared_secret)
        
        return aes_key
    
    def _register(self, email: str, username: str, password: str, aes_key: bytes) -> bool:
        """Register a new user."""
        # Create registration data (plaintext password - will be encrypted)
        register_data = {
            "type": "register",
            "email": email,
            "username": username,
            "pwd": password  # Plaintext password
        }
        
        # Encrypt registration data
        data_json = json.dumps(register_data).encode('utf-8')
        encrypted_data = encrypt(aes_key, data_json)
        
        # Send encrypted registration
        self._send_message({
            "type": "register",
            "encrypted_data": b64e(encrypted_data)
        })
        
        # Receive response
        msg = self._receive_message()
        if msg.get("type") == "register_success":
            print(f"Registration successful: {msg.get('message')}")
            return True
        else:
            print(f"Registration failed: {msg.get('message', 'Unknown error')}")
            return False
    
    def _login(self, email: str, password: str, aes_key: bytes) -> bool:
        """Login with credentials."""
        # Create login data (plaintext password - will be encrypted)
        login_data = {
            "type": "login",
            "email": email,
            "pwd": password,  # Plaintext password
            "nonce": b64e(secrets.token_bytes(16))
        }
        
        # Encrypt login data
        data_json = json.dumps(login_data).encode('utf-8')
        encrypted_data = encrypt(aes_key, data_json)
        
        # Send encrypted login
        self._send_message({
            "type": "login",
            "encrypted_data": b64e(encrypted_data)
        })
        
        # Receive response
        msg = self._receive_message()
        if msg.get("type") == "login_success":
            print(f"Login successful: {msg.get('message')}")
            return True
        else:
            print(f"Login failed: {msg.get('message', 'Unknown error')}")
            return False
    
    def _send_chat_message(self, plaintext: str, server_cert: str, transcript: Transcript) -> tuple[bool, str, str]:
        """Send an encrypted chat message. Returns (success, ciphertext_b64, signature_b64)."""
        # Increment sequence number
        self.seqno += 1
        
        # Encrypt message
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext = encrypt(self.session_key, plaintext_bytes)
        ciphertext_b64 = b64e(ciphertext)
        
        # Get timestamp
        timestamp = now_ms()
        
        # Compute hash: SHA256(seqno || ts || ct)
        seqno_bytes = str(self.seqno).encode('utf-8')
        ts_bytes = str(timestamp).encode('utf-8')
        ct_bytes = ciphertext
        hash_input = seqno_bytes + ts_bytes + ct_bytes
        hash_bytes = hashlib.sha256(hash_input).digest()
        
        # Sign hash
        signature = sign(self.client_private_key, hash_bytes)
        signature_b64 = b64e(signature)
        
        # Create message
        chat_msg = ChatMessage(
            seqno=self.seqno,
            ts=timestamp,
            ct=ciphertext_b64,
            sig=signature_b64
        )
        
        # Send message
        self._send_message(chat_msg.model_dump())
        
        # Add to transcript
        transcript.add_message(self.seqno, timestamp, ciphertext_b64, signature_b64)
        
        # Wait for ACK
        try:
            msg = self._receive_message()
            if msg.get("type") == "ack" and msg.get("seqno") == self.seqno:
                return True, ciphertext_b64, signature_b64
            else:
                print(f"Error: Unexpected response: {msg}")
                return False, ciphertext_b64, signature_b64
        except Exception as e:
            print(f"Error receiving ACK: {str(e)}")
            return False, ciphertext_b64, signature_b64
    
    def connect(self):
        """Connect to server and establish secure session."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        print(f"Connected to {self.host}:{self.port}")
        
        # Phase 1: Certificate Exchange
        server_cert = self._exchange_certificates()
        if not server_cert:
            return False
        
        # Phase 2: Temporary DH for registration/login
        temp_aes_key = self._perform_dh_exchange(is_temporary=True)
        if not temp_aes_key:
            return False
        
        # Phase 3: Registration or Login
        print("\n=== Authentication ===")
        choice = input("Register (r) or Login (l)? ").strip().lower()
        
        if choice == "r":
            email = input("Email: ").strip()
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            if not self._register(email, username, password, temp_aes_key):
                return False
        elif choice == "l":
            email = input("Email: ").strip()
            password = input("Password: ").strip()
            if not self._login(email, password, temp_aes_key):
                return False
        else:
            print("Invalid choice")
            return False
        
        # Phase 4: Session Key Establishment
        self.session_key = self._perform_dh_exchange(is_temporary=False)
        if not self.session_key:
            return False
        
        print("\n=== Session Established ===")
        print("You can now send messages. Type 'quit' to end session.")
        
        return server_cert
    
    def chat_loop(self, server_cert: str):
        """Main chat loop."""
        # Initialize transcript
        server_fingerprint = get_fingerprint(server_cert)
        session_id = f"{self.host}_{self.port}_{now_ms()}"
        transcript = Transcript(session_id, server_fingerprint)
        
        try:
            while True:
                # Read user input
                message = input("\nYou: ").strip()
                
                if message.lower() == "quit":
                    break
                
                if not message:
                    continue
                
                # Send message
                success, ct, sig = self._send_chat_message(message, server_cert, transcript)
                if not success:
                    print("Failed to send message")
        
        except KeyboardInterrupt:
            print("\nInterrupted by user")
        finally:
            # Phase 6: Generate Session Receipt
            transcript_hash = transcript.compute_transcript_hash()
            receipt = SessionReceipt(
                peer="client",
                first_seq=transcript.get_first_seq(),
                last_seq=transcript.get_last_seq(),
                transcript_sha256=transcript_hash,
                sig=b64e(sign(self.client_private_key, transcript_hash.encode('utf-8')))
            )
            
            # Send receipt to server (optional, or just save locally)
            try:
                self._send_message({"type": "quit"})
                # Receive server receipt if sent
                try:
                    msg = self._receive_message()
                    if msg.get("type") == "receipt":
                        print("\nReceived server receipt")
                        # Save server receipt
                        receipt_file = f"transcripts/receipt_{session_id}_server.json"
                        with open(receipt_file, 'w') as f:
                            json.dump(msg, f, indent=2)
                        print(f"Server receipt saved to {receipt_file}")
                except:
                    pass
            except:
                pass
            
            # Save client receipt
            receipt_file = f"transcripts/receipt_{session_id}_client.json"
            with open(receipt_file, 'w') as f:
                json.dump(receipt.model_dump(), f, indent=2)
            print(f"Client receipt saved to {receipt_file}")
            
            # Save transcript
            transcript.save_to_file()
            print("\nSession ended. Receipt generated.")
    
    def run(self):
        """Run the client."""
        try:
            server_cert = self.connect()
            if server_cert:
                self.chat_loop(server_cert)
        except Exception as e:
            print(f"Error: {str(e)}")
            import traceback
            traceback.print_exc()
        finally:
            if self.sock:
                self.sock.close()


def main():
    """Main entry point."""
    client = SecureChatClient()
    client.run()


if __name__ == "__main__":
    main()
