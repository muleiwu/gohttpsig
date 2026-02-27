# Secure Credential Storage Example

This example demonstrates **how to securely store SecretAccessKey** for server-side signature verification.

## ⚠️ Critical Security Notice

**DO NOT store SecretAccessKey as plaintext or hashed in your database!**

- ❌ **Plaintext**: `secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`
- ❌ **Hashed**: `secret_hash = SHA256("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")`
- ✅ **Encrypted**: `encrypted_secret = AES256_GCM_Encrypt("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", encryption_key)`

## Why Encryption Instead of Hashing?

AWS Signature V4 uses **HMAC (symmetric encryption)**:

1. **Client**: Uses `SecretAccessKey` to compute signature
2. **Server**: Uses the **same** `SecretAccessKey` to recompute signature
3. **Comparison**: Signatures must match

You **cannot** use a hash because:
- Hashing is one-way and irreversible
- Server needs the original `SecretAccessKey` to compute HMAC
- Hash cannot be used to compute HMAC

## Running the Example

### Basic Demo (No Database Required)

```bash
cd examples/secure-storage
go run .
```

This will demonstrate:
- Generating a secure encryption key
- Encrypting/decrypting credentials
- The complete workflow

### With PostgreSQL Database

1. Set up PostgreSQL:
```bash
createdb gohttpsig
```

2. Generate an encryption key:
```bash
# Generate 32-byte (256-bit) key
openssl rand -hex 32
```

3. Set environment variables:
```bash
export DATABASE_URL="postgres://user:password@localhost/gohttpsig?sslmode=disable"
export ENCRYPTION_KEY="<your-64-char-hex-key-from-step-2>"
```

4. Uncomment the `runWithDatabase()` call in `main.go` and run:
```bash
go run .
```

## Implementation Details

### Encryption Algorithm

- **Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key Size**: 32 bytes (256 bits)
- **Authenticated Encryption**: Provides both confidentiality and authenticity
- **Nonce**: Randomly generated for each encryption

### Database Schema

```sql
CREATE TABLE api_credentials (
    id SERIAL PRIMARY KEY,
    access_key_id VARCHAR(128) UNIQUE NOT NULL,
    encrypted_secret_key TEXT NOT NULL,        -- AES-256-GCM encrypted
    old_encrypted_secret_key TEXT,             -- For rotation
    created_at TIMESTAMP DEFAULT NOW(),
    last_rotated_at TIMESTAMP,
    last_used_at TIMESTAMP,
    is_active BOOLEAN DEFAULT true
);

CREATE TABLE credential_audit_log (
    id SERIAL PRIMARY KEY,
    access_key_id VARCHAR(128),
    action VARCHAR(50),                        -- 'created', 'accessed', 'rotated', 'revoked'
    result VARCHAR(20),                        -- 'success', 'failure'
    ip_address INET,
    timestamp TIMESTAMP DEFAULT NOW()
);
```

## Security Best Practices

### 1. Encryption Key Management

**Option A: Environment Variables**
```bash
export ENCRYPTION_KEY=$(openssl rand -hex 32)
```

**Option B: Cloud KMS (Recommended for Production)**
```go
// AWS KMS
key := getFromAWSKMS("alias/gohttpsig-encryption-key")

// GCP KMS
key := getFromGCPKMS("projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY")

// Azure Key Vault
key := getFromAzureKeyVault("https://vault.azure.net", "encryption-key")
```

**Option C: HashiCorp Vault**
```go
key := getFromVault("secret/data/gohttpsig/encryption-key")
```

### 2. Credential Rotation

```go
// Rotate every 90 days
err := store.RotateCredentials(ctx, accessKeyID, newSecretKey)

// Keep old key for 24-hour grace period
// Allows smooth transition without service interruption
```

### 3. Audit Logging

```go
// Every credential access is logged
credential_audit_log:
- access_key_id: AKIAIOSFODNN7EXAMPLE
- action: accessed
- result: success
- ip_address: 192.168.1.100
- timestamp: 2026-02-27 12:30:45
```

### 4. Access Control

```go
// Check if credentials are revoked
if !isActive {
    return ErrCredentialRevoked
}

// Monitor for suspicious activity
if failureCount > threshold {
    autoRevoke(accessKeyID)
}
```

## Production Deployment Checklist

- [ ] Use cloud KMS or dedicated key management system
- [ ] Store encryption keys separately from database
- [ ] Enable database encryption at rest
- [ ] Use HTTPS for all API communications
- [ ] Implement credential rotation (every 90 days)
- [ ] Set up audit logging and monitoring
- [ ] Configure alerts for suspicious activity
- [ ] Use temporary credentials when possible
- [ ] Regularly review and revoke unused credentials
- [ ] Test backup and recovery procedures

## Common Mistakes to Avoid

### ❌ Mistake 1: Storing Plaintext
```go
// NEVER DO THIS!
db.Exec("INSERT INTO credentials (access_key, secret_key) VALUES (?, ?)",
    accessKey, secretKey)
```

### ❌ Mistake 2: Storing Hash
```go
// WRONG! Cannot recompute HMAC from hash
hash := sha256.Sum256([]byte(secretKey))
db.Exec("INSERT INTO credentials (access_key, secret_hash) VALUES (?, ?)",
    accessKey, hash)
```

### ✅ Correct: Storing Encrypted
```go
// CORRECT!
encrypted := encrypt(secretKey, encryptionKey)
db.Exec("INSERT INTO credentials (access_key, encrypted_secret) VALUES (?, ?)",
    accessKey, encrypted)
```

## Further Reading

- [NIST Guidelines on Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [AWS KMS Best Practices](https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html)
