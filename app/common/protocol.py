"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""

from pydantic import BaseModel
from typing import Optional


class HelloMessage(BaseModel):
    """Client hello with certificate and nonce."""
    type: str = "hello"
    client_cert: str  # PEM-encoded certificate
    nonce: str  # base64-encoded nonce


class ServerHelloMessage(BaseModel):
    """Server hello with certificate and nonce."""
    type: str = "server_hello"
    server_cert: str  # PEM-encoded certificate
    nonce: str  # base64-encoded nonce


class RegisterMessage(BaseModel):
    """Registration message with encrypted credentials."""
    type: str = "register"
    email: str
    username: str
    pwd: str  # base64(sha256(salt||pwd))
    salt: str  # base64-encoded salt


class LoginMessage(BaseModel):
    """Login message with encrypted credentials."""
    type: str = "login"
    email: str
    pwd: str  # base64(sha256(salt||pwd))
    nonce: str  # base64-encoded nonce


class DHClientMessage(BaseModel):
    """Client Diffie-Hellman parameters."""
    type: str = "dh_client"
    g: int  # generator
    p: int  # prime modulus
    A: int  # client public value (g^a mod p)


class DHServerMessage(BaseModel):
    """Server Diffie-Hellman response."""
    type: str = "dh_server"
    B: int  # server public value (g^b mod p)


class ChatMessage(BaseModel):
    """Encrypted chat message with signature."""
    type: str = "msg"
    seqno: int  # sequence number
    ts: int  # unix timestamp in milliseconds
    ct: str  # base64-encoded ciphertext
    sig: str  # base64-encoded RSA signature


class SessionReceipt(BaseModel):
    """Session receipt for non-repudiation."""
    type: str = "receipt"
    peer: str  # "client" or "server"
    first_seq: int  # first sequence number
    last_seq: int  # last sequence number
    transcript_sha256: str  # hex-encoded transcript hash
    sig: str  # base64-encoded RSA signature
