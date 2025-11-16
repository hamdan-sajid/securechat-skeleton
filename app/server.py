"""Server skeleton — plain TCP; no TLS. See assignment spec."""

import os
import json
import socket
import secrets
import threading
import hashlib
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
from app.storage.db import register_user, verify_user, get_user_salt, get_username_by_email
from app.storage.transcript import Transcript, get_certificate_fingerprint as get_fingerprint

load_dotenv()


class SecureChatServer:
    """Secure chat server implementing CIANR protocol."""
    
    def __init__(self, host: str = "localhost", port: int = 8888):
        self.host = host
        self.port = port
        self.ca_cert_path = os.getenv("CA_CERT_PATH", "certs/ca_cert.pem")
        self.server_cert_path = os.getenv("SERVER_CERT_PATH", "certs/server_cert.pem")
        self.server_key_path = os.getenv("SERVER_KEY_PATH", "certs/server_key.pem")
        self.server_cert_pem = self._load_cert_pem()
        self.server_private_key = load_private_key(self.server_key_path)
        self.expected_client_cn = os.getenv("CLIENT_CN", "client.local")
    
    def _load_cert_pem(self) -> str:
        """Load server certificate as PEM string."""
        with open(self.server_cert_path, 'r') as f:
            return f.read()
    
    def _send_message(self, conn: socket.socket, message: dict):
        """Send JSON message over socket."""
        data = json.dumps(message) + "\n"
        conn.sendall(data.encode('utf-8'))
    
    def _receive_message(self, conn: socket.socket) -> dict:
        """Receive JSON message from socket."""
        buffer = b""
        while b"\n" not in buffer:
            chunk = conn.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed")
            buffer += chunk
        line = buffer.split(b"\n", 1)[0]
        return json.loads(line.decode('utf-8'))
    
    def _handle_hello(self, conn: socket.socket, msg: dict) -> Optional[str]:
        """Handle client hello and send server hello."""
        hello = HelloMessage(**msg)
        
        # Validate client certificate
        is_valid, error = validate_certificate(
            hello.client_cert,
            self.ca_cert_path,
            self.expected_client_cn
        )
        
        if not is_valid:
            self._send_message(conn, {"type": "error", "message": error})
            return None
        
        # Generate server nonce
        server_nonce = secrets.token_bytes(16)
        
        # Send server hello
        server_hello = ServerHelloMessage(
            server_cert=self.server_cert_pem,
            nonce=b64e(server_nonce)
        )
        self._send_message(conn, server_hello.model_dump())
        
        return hello.client_cert
    
    def _handle_dh_exchange(self, conn: socket.socket, is_temporary: bool = False) -> Optional[bytes]:
        """Handle DH key exchange and return derived AES key."""
        # Receive client DH parameters
        msg = self._receive_message(conn)
        dh_client = DHClientMessage(**msg)
        
        # Generate server private key
        server_private = generate_private_key()
        
        # Compute server public value
        server_public = compute_public_value(server_private, dh_client.g, dh_client.p)
        
        # Send server public value
        dh_server = DHServerMessage(B=server_public)
        self._send_message(conn, dh_server.model_dump())
        
        # Derive shared secret and AES key
        shared_secret = derive_shared_secret(server_private, dh_client.A, dh_client.p)
        aes_key = derive_aes_key(shared_secret)
        
        return aes_key
    
    def _handle_register(self, conn: socket.socket, aes_key: bytes, first_msg: dict):
        """Handle user registration."""
        # Use the already received registration message
        encrypted_data = b64d(first_msg.get("encrypted_data", ""))
        
        # Decrypt
        try:
            decrypted = decrypt(aes_key, encrypted_data)
            data = json.loads(decrypted.decode('utf-8'))
            # Extract registration data (plaintext password after decryption)
            email = data.get("email")
            username = data.get("username")
            plaintext_password = data.get("pwd")  # Plaintext password after decryption
        except Exception as e:
            self._send_message(conn, {"type": "error", "message": f"Decryption failed: {str(e)}"})
            return False, None
        
        # Register user (db layer will generate salt and hash)
        success, message = register_user(email, username, plaintext_password)
        
        if success:
            self._send_message(conn, {"type": "register_success", "message": message})
            return True, username
        else:
            self._send_message(conn, {"type": "error", "message": message})
            return False, None
    
    def _handle_login(self, conn: socket.socket, aes_key: bytes, client_cert: str, first_msg: dict):
        """Handle user login."""
        # Use the already received login message
        encrypted_data = b64d(first_msg.get("encrypted_data", ""))
        
        # Decrypt
        try:
            decrypted = decrypt(aes_key, encrypted_data)
            data = json.loads(decrypted.decode('utf-8'))
            # Extract email and plaintext password
            email = data.get("email")
            plaintext_password = data.get("pwd")  # Plaintext password after decryption
        except Exception as e:
            self._send_message(conn, {"type": "error", "message": f"Decryption failed: {str(e)}"})
            return False, None
        
        # Get user salt
        salt = get_user_salt(email)
        if not salt:
            self._send_message(conn, {"type": "error", "message": "Invalid credentials"})
            return False, None
        
        # Verify password by recomputing hash
        if verify_user(email, plaintext_password, salt):
            self._send_message(conn, {"type": "login_success", "message": "Login successful"})
            username = get_username_by_email(email)
            return True, username
        else:
            self._send_message(conn, {"type": "error", "message": "Invalid credentials"})
            return False, None
    
    def _handle_chat_message(self, conn: socket.socket, msg: dict, session_key: bytes, 
                            transcript: Transcript, expected_seqno: int, client_cert: str, user_label: str) -> tuple[bool, int]:
        """Handle encrypted chat message."""
        chat_msg = ChatMessage(**msg)
        
        # Check sequence number (replay protection)
        if chat_msg.seqno <= expected_seqno:
            print(f"⚠️  REPLAY DETECTED: Message with seqno={chat_msg.seqno} rejected (expected > {expected_seqno})")
            self._send_message(conn, {"type": "error", "message": "REPLAY"})
            return False, expected_seqno
        
        # Check timestamp (freshness)
        current_time = now_ms()
        if abs(current_time - chat_msg.ts) > 300000:  # 5 minutes tolerance
            print(f"⚠️  STALE MESSAGE: Message timestamp {chat_msg.ts} is too old (current: {current_time})")
            self._send_message(conn, {"type": "error", "message": "STALE"})
            return False, expected_seqno
        
        # Verify signature
        ciphertext_bytes = b64d(chat_msg.ct)
        # Hash: SHA256(seqno || ts || ct)
        seqno_bytes = str(chat_msg.seqno).encode('utf-8')
        ts_bytes = str(chat_msg.ts).encode('utf-8')
        hash_input = seqno_bytes + ts_bytes + ciphertext_bytes
        hash_bytes = hashlib.sha256(hash_input).digest()
        
        client_public_key = load_public_key_from_cert(client_cert)
        signature_bytes = b64d(chat_msg.sig)
        
        if not verify(client_public_key, signature_bytes, hash_bytes):
            print(f"❌ SIG_FAIL: Signature verification failed for message seqno={chat_msg.seqno} from {user_label}")
            self._send_message(conn, {"type": "error", "message": "SIG_FAIL"})
            return False, expected_seqno
        
        # Decrypt message
        try:
            plaintext = decrypt(session_key, ciphertext_bytes)
            # Remove padding and decode
            message_text = plaintext.decode('utf-8').rstrip('\x00').rstrip()
            print(f"[{user_label}]: {message_text}")
            
            # Add to transcript
            transcript.add_message(chat_msg.seqno, chat_msg.ts, chat_msg.ct, chat_msg.sig)
            
            self._send_message(conn, {"type": "ack", "seqno": chat_msg.seqno})
            return True, chat_msg.seqno
        except Exception as e:
            self._send_message(conn, {"type": "error", "message": f"Decryption failed: {str(e)}"})
            return False, expected_seqno
    
    def _handle_client(self, conn: socket.socket, addr: tuple):
        """Handle a client connection."""
        print(f"Client connected from {addr}")
        client_cert = None
        session_key = None
        transcript = None
        expected_seqno = 0
        user_label = "client"
        
        try:
            # Phase 1: Certificate Exchange
            msg = self._receive_message(conn)
            if msg.get("type") != "hello":
                self._send_message(conn, {"type": "error", "message": "Expected hello message"})
                return
            
            client_cert = self._handle_hello(conn, msg)
            if not client_cert:
                return
            
            # Phase 2: Temporary DH for registration/login
            temp_aes_key = self._handle_dh_exchange(conn, is_temporary=True)
            
            # Phase 3: Registration or Login
            msg = self._receive_message(conn)
            authenticated = False
            user_label = "client"
            
            if msg.get("type") == "register":
                authenticated, username = self._handle_register(conn, temp_aes_key, msg)
            elif msg.get("type") == "login":
                authenticated, username = self._handle_login(conn, temp_aes_key, client_cert, msg)
            else:
                self._send_message(conn, {"type": "error", "message": "Expected register or login"})
                return
            
            if not authenticated:
                return
            
            if username:
                user_label = username
                print(f"Authenticated user: {user_label}")
            else:
                print("Authenticated user: <unknown>")
            
            # Phase 4: Session Key Establishment
            session_key = self._handle_dh_exchange(conn, is_temporary=False)
            
            # Initialize transcript
            client_fingerprint = get_fingerprint(client_cert)
            session_id = f"{addr[0]}_{addr[1]}_{now_ms()}"
            transcript = Transcript(session_id, client_fingerprint)
            
            print("Session established. Ready for messages. Type 'quit' to end session.")
            
            # Phase 5: Chat Loop
            while True:
                msg = self._receive_message(conn)
                
                if msg.get("type") == "msg":
                    success, expected_seqno = self._handle_chat_message(
                        conn, msg, session_key, transcript, expected_seqno, client_cert, user_label
                    )
                    if not success:
                        continue
                elif msg.get("type") == "quit":
                    break
                else:
                    self._send_message(conn, {"type": "error", "message": "Unknown message type"})
            
            # Phase 6: Generate Session Receipt
            transcript_hash = transcript.compute_transcript_hash()
            receipt = SessionReceipt(
                peer="server",
                first_seq=transcript.get_first_seq(),
                last_seq=transcript.get_last_seq(),
                transcript_sha256=transcript_hash,
                sig=b64e(sign(self.server_private_key, transcript_hash.encode('utf-8')))
            )
            self._send_message(conn, receipt.model_dump())
            
            # Save transcript
            transcript.save_to_file()
            
            # Save server receipt
            import os
            receipt_dir = "transcripts"
            os.makedirs(receipt_dir, exist_ok=True)
            receipt_file = os.path.join(receipt_dir, f"receipt_{transcript.session_id}_server.json")
            with open(receipt_file, 'w') as f:
                json.dump(receipt.model_dump(), f, indent=2)
            print(f"Server receipt saved to {receipt_file}")
            print("Session ended. Receipt generated.")
            
        except Exception as e:
            print(f"Error handling client: {str(e)}")
            import traceback
            traceback.print_exc()
        finally:
            conn.close()
            print(f"Client {addr} disconnected")
    
    def start(self):
        """Start the server."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(5)
        
        print(f"Secure Chat Server listening on {self.host}:{self.port}")
        print("Waiting for clients...")
        
        while True:
            conn, addr = sock.accept()
            client_thread = threading.Thread(target=self._handle_client, args=(conn, addr))
            client_thread.daemon = True
            client_thread.start()


def main():
    """Main entry point."""
    server = SecureChatServer()
    server.start()


if __name__ == "__main__":
    main()
