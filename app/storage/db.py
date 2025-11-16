"""MySQL users table + salted hashing (no chat storage)."""

import os
import secrets
import hashlib
import hmac
from typing import Optional, Tuple
import pymysql
from dotenv import load_dotenv

load_dotenv()


def get_db_connection():
    """Get MySQL database connection."""
    return pymysql.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        port=int(os.getenv('DB_PORT', 3306)),
        user=os.getenv('DB_USER', 'scuser'),
        password=os.getenv('DB_PASSWORD', 'scpass'),
        database=os.getenv('DB_NAME', 'securechat'),
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )


def init_database():
    """Initialize database tables."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    email VARCHAR(255) NOT NULL,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    salt VARBINARY(16) NOT NULL,
                    pwd_hash CHAR(64) NOT NULL,
                    PRIMARY KEY (username)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)
        conn.commit()
        print("Database initialized successfully")
    finally:
        conn.close()


def generate_salt() -> bytes:
    """Generate a random 16-byte salt."""
    return secrets.token_bytes(16)


def hash_password(salt: bytes, password: str) -> str:
    """
    Compute salted password hash: SHA256(salt || password).
    
    Args:
        salt: 16-byte salt
        password: plaintext password
        
    Returns:
        hex-encoded hash (64 characters)
    """
    data = salt + password.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def register_user(email: str, username: str, password: str) -> Tuple[bool, str]:
    """
    Register a new user with salted password hash.
    
    Args:
        email: user email
        username: username (must be unique)
        password: plaintext password
        
    Returns:
        (success, message) tuple
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Check if username already exists
            cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                return False, "Username already exists"
            
            # Check if email already exists
            cursor.execute("SELECT email FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                return False, "Email already registered"
            
            # Generate salt and hash password
            salt = generate_salt()
            pwd_hash = hash_password(salt, password)
            
            # Insert user
            cursor.execute(
                "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
                (email, username, salt, pwd_hash)
            )
        conn.commit()
        return True, "Registration successful"
    except Exception as e:
        conn.rollback()
        return False, f"Registration failed: {str(e)}"
    finally:
        conn.close()


def verify_user(email: str, password: str, salt: bytes) -> bool:
    """
    Verify user credentials by recomputing hash.
    
    Args:
        email: user email
        password: plaintext password
        salt: salt bytes (from database)
        
    Returns:
        True if password matches, False otherwise
    """
    pwd_hash = hash_password(salt, password)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT pwd_hash FROM users WHERE email = %s",
                (email,)
            )
            result = cursor.fetchone()
            if not result:
                return False
            # Constant-time comparison
            return hmac.compare_digest(result['pwd_hash'], pwd_hash)
    finally:
        conn.close()


def get_user_salt(email: str) -> Optional[bytes]:
    """
    Get salt for a user by email.
    
    Args:
        email: user email
        
    Returns:
        salt bytes or None if user not found
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT salt FROM users WHERE email = %s", (email,))
            result = cursor.fetchone()
            if result:
                return result['salt']
            return None
    finally:
        conn.close()


def get_username_by_email(email: str) -> Optional[str]:
    """Fetch username for a given email."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT username FROM users WHERE email = %s", (email,))
            result = cursor.fetchone()
            if result:
                return result["username"]
            return None
    finally:
        conn.close()


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--init":
        init_database()
