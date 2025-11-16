# SecureChat – Assignment #2

A console-based, PKI-enabled Secure Chat System demonstrating **Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**.

## 🚀 Quick Start

### 1. Setup Environment

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # Linux/Mac
# OR
.venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment

Create a `.env` file in the project root:

```env
DB_HOST=localhost
DB_PORT=3307
DB_USER=scuser
DB_PASSWORD=scpass
DB_NAME=securechat

CA_CERT_PATH=certs/ca_cert.pem
SERVER_CERT_PATH=certs/server_cert.pem
SERVER_KEY_PATH=certs/server_key.pem
CLIENT_CERT_PATH=certs/client_cert.pem
CLIENT_KEY_PATH=certs/client_key.pem

SERVER_CN=server.local
CLIENT_CN=client.local

SERVER_HOST=localhost
SERVER_PORT=8888
```

### 3. Start MySQL Database

```bash
# Start MySQL container
docker run -d --name securechat-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3307:3306 \
  mysql:8

# Initialize database tables
python3 -m app.storage.db --init
```

### 4. Generate Certificates

```bash
# Generate Root CA
python3 scripts/gen_ca.py --name "FAST-NU Root CA" --out certs

# Generate server certificate
python3 scripts/gen_cert.py --cn server.local --out server --dir certs

# Generate client certificate
python3 scripts/gen_cert.py --cn client.local --out client --dir certs
```

### 5. Run the System

**Terminal 1 - Start Server:**
```bash
python3 -m app.server
```

**Terminal 2 - Start Client:**
```bash
python3 -m app.client
```

## 📖 Usage

1. **Client connects** → Certificate exchange happens automatically
2. **Choose authentication:**
   - Type `r` to register (new user)
   - Type `l` to login (existing user)
3. **Enter credentials:**
   - Email, Username (for registration), Password
4. **Chat:**
   - Type messages and press Enter
   - Server displays: `[username]: message`
   - Type `quit` to end session
5. **Session ends:**
   - Transcripts and receipts are saved automatically in `transcripts/` folder

## 🧪 Testing

### Test 1: Wireshark - Encrypted Payloads

1. Start Wireshark
2. Set display filter: `tcp.port == 8888`
3. Start capture
4. Run server and client, send messages
5. **Verify:** Only encrypted payloads visible (base64 ciphertext), no plaintext

### Test 2: Invalid Certificates → BAD_CERT

#### Self-Signed Certificate
```bash
# Generate self-signed cert
openssl req -x509 -newkey rsa:2048 -keyout certs/fake_client_key.pem \
  -out certs/fake_client_cert.pem -days 365 -nodes -subj "/CN=fake.client"

# Update .env: CLIENT_CERT_PATH=certs/fake_client_cert.pem
# Run client → Should see: BAD_CERT: Certificate is self-signed
```

#### Expired Certificate
```bash
# Generate expired cert
python3 scripts/gen_expired_cert.py --cn expired.client.local --out expired_client

# Update .env: CLIENT_CERT_PATH=certs/expired_client_cert.pem
# Run client → Should see: BAD_CERT: Certificate expired or not yet valid
```

#### Forged Certificate
```bash
# Generate forged cert (claims CA issuer but wrong signature)
python3 scripts/gen_forged_cert.py --cn forged.client.local --out forged_client

# Update .env: CLIENT_CERT_PATH=certs/forged_client_cert.pem
# Run client → Should see: BAD_CERT: Certificate not signed by trusted CA
```

#### Wrong Common Name
```bash
# Edit .env: SERVER_CN=wrong.server.local
# Restart server, run client
# Should see: BAD_CERT: Common Name mismatch
```

### Test 3: Tampering → SIG_FAIL

```bash
# Run live tampering test
python3 scripts/test_tamper_live.py <email> <password>

# Expected: Server responds with SIG_FAIL
# Server console shows: ❌ SIG_FAIL: Signature verification failed
```

### Test 4: Replay → REPLAY

```bash
# Run live replay test
python3 scripts/test_replay_live.py <email> <password>

# Expected: Server responds with REPLAY
# Server console shows: ⚠️ REPLAY DETECTED: Message with seqno=X rejected
```

### Test 5: Non-Repudiation - Offline Verification

```bash
# After completing a chat session, verify transcript and receipt
python3 scripts/verify_receipt.py \
  --transcript transcripts/transcript_<session_id>.txt \
  --receipt transcripts/receipt_<session_id>_server.json \
  --cert certs/server_cert.pem \
  --message-cert certs/client_cert.pem

# Expected: All verifications succeeded

# To test tampering detection:
# 1. Edit transcript file (modify ciphertext)
# 2. Run verification again
# 3. Should see: Signature verification FAILED
```

## 📁 Project Structure

```
securechat-skeleton/
├── app/
│   ├── client.py              # Client implementation
│   ├── server.py              # Server implementation
│   ├── crypto/
│   │   ├── aes.py             # AES-128 encryption
│   │   ├── dh.py              # Diffie-Hellman key exchange
│   │   ├── pki.py             # Certificate validation
│   │   └── sign.py            # RSA signing/verification
│   ├── common/
│   │   ├── protocol.py        # Message models
│   │   └── utils.py           # Helper functions
│   └── storage/
│       ├── db.py              # MySQL user storage
│       └── transcript.py      # Transcript management
├── scripts/
│   ├── gen_ca.py              # Generate Root CA
│   ├── gen_cert.py            # Generate certificates
│   ├── gen_expired_cert.py    # Generate expired certs (testing)
│   ├── gen_forged_cert.py    # Generate forged certs (testing)
│   ├── test_tamper_live.py   # Live tampering test
│   ├── test_replay_live.py   # Live replay test
│   └── verify_receipt.py     # Verify transcripts/receipts
├── certs/                     # Certificates (gitignored)
├── transcripts/               # Session transcripts (gitignored)
├── .env                       # Configuration (gitignored)
└── requirements.txt           # Dependencies
```

## 🔐 Security Features

- **Confidentiality:** AES-128 encryption for all sensitive data
- **Integrity:** SHA-256 hashing with RSA signatures on all messages
- **Authenticity:** X.509 certificate-based mutual authentication
- **Non-Repudiation:** Signed session receipts and transcripts
- **Replay Protection:** Sequence number validation
- **Freshness:** Timestamp validation

## 🗄️ Database Schema

**Table: `users`**
- `email` VARCHAR(255) - User email
- `username` VARCHAR(255) UNIQUE - Username (PRIMARY KEY)
- `salt` VARBINARY(16) - 16-byte random salt
- `pwd_hash` CHAR(64) - SHA-256(salt || password) as hex string

**Note:** Chat messages are NOT stored in database. Only user credentials.

## 📝 Transcript Format

Each line in transcript file:
```
seqno|timestamp|base64_ciphertext|base64_signature|certificate_fingerprint
```

## 🔍 Viewing Database

```bash
# Connect to MySQL
docker exec -it securechat-db mysql -uscuser -pscpass securechat

# View users
SELECT email, username, HEX(salt) as salt_hex, pwd_hash FROM users;

# Exit
EXIT;
```

## 🛠️ Troubleshooting

**Port already in use:**
- Change `SERVER_PORT` in `.env` or stop conflicting service

**Database connection failed:**
- Check Docker container is running: `docker ps`
- Verify port mapping: `3307:3306`

**Certificate errors:**
- Regenerate certificates (Step 4)
- Check `.env` paths are correct

**Module not found:**
- Ensure virtual environment is activated
- Run from project root directory

## 📚 Key Commands Reference

```bash
# Database
python3 -m app.storage.db --init

# Certificates
python3 scripts/gen_ca.py --name "FAST-NU Root CA" --out certs
python3 scripts/gen_cert.py --cn server.local --out server --dir certs
python3 scripts/gen_cert.py --cn client.local --out client --dir certs

# Testing
python3 scripts/gen_expired_cert.py --cn expired.client.local --out expired_client
python3 scripts/gen_forged_cert.py --cn forged.client.local --out forged_client
python3 scripts/test_tamper_live.py <email> <password>
python3 scripts/test_replay_live.py <email> <password>
python3 scripts/verify_receipt.py --transcript <file> --receipt <file> --cert <cert> --message-cert <cert>

# Run
python3 -m app.server
python3 -m app.client
```

## ⚠️ Important Notes

- **No TLS/SSL:** All crypto operations are at application layer (plain TCP sockets)
- **Using Libraries:** AES, RSA, DH implemented using `cryptography` library (not custom math)
- **Secrets:** Never commit certificates, keys, or `.env` files to Git
- **Transcripts:** Saved automatically in `transcripts/` folder after each session

## 📊 Test Evidence Checklist

- [ ] Wireshark capture showing encrypted payloads only
- [ ] Invalid certificate tests (self-signed, expired, forged, wrong CN) → BAD_CERT
- [ ] Tampering test → SIG_FAIL (server console + client response)
- [ ] Replay test → REPLAY (server console + client response)
- [ ] Non-repudiation: Successful verification of transcript and receipt
- [ ] Non-repudiation: Failed verification after tampering transcript

## 📄 License

This is an academic assignment. All code follows the assignment specifications.
