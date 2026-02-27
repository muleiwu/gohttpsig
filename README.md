# gohttpsig

[![Go Reference](https://pkg.go.dev/badge/github.com/muleiwu/gohttpsig.svg)](https://pkg.go.dev/github.com/muleiwu/gohttpsig)
[![Go Report Card](https://goreportcard.com/badge/github.com/muleiwu/gohttpsig)](https://goreportcard.com/report/github.com/muleiwu/gohttpsig)
[![License](https://img.shields.io/github/license/muleiwu/gohttpsig)](LICENSE)

English | [简体中文](README.zh-CN.md)

A complete Go implementation of AWS Signature Version 4 for HTTP request signing and verification. This library enables both client-side request signing and server-side signature verification using AWS SigV4, making it easy to implement secure authentication for your HTTP APIs.

## Features

- ✅ **Client-side signing** - Sign outgoing HTTP requests with AWS SigV4 credentials
- ✅ **Server-side verification** - Validate incoming signed requests for authentication
- ✅ **RFC 3986 compliant** - Strict URI encoding per AWS SigV4 specification
- ✅ **Presigned URLs** - Generate time-limited presigned URLs
- ✅ **Zero dependencies** - Uses only Go standard library
- ✅ **Thread-safe** - Safe for concurrent use
- ✅ **Comprehensive tests** - Full test coverage including AWS compliance
- ✅ **Constant-time comparison** - Prevents timing attacks during verification
- ✅ **Session token support** - Works with temporary credentials

## Installation

```bash
go get github.com/muleiwu/gohttpsig
```

## Quick Start

### Client: Signing Requests

```go
package main

import (
    "context"
    "net/http"
    "github.com/muleiwu/gohttpsig"
)

func main() {
    // Create credentials
    creds := &gohttpsig.Credentials{
        AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
        SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    }

    // Create signer
    provider := gohttpsig.NewStaticCredentialsProvider(creds)
    signer := gohttpsig.NewSigner(provider)

    // Create and sign request
    req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
    signed, err := signer.Sign(context.Background(), req, "myservice", "us-east-1")
    if err != nil {
        panic(err)
    }

    // Send the signed request
    resp, err := http.DefaultClient.Do(signed.Request)
    // ... handle response
}
```

### Server: Verifying Requests

```go
package main

import (
    "context"
    "net/http"
    "github.com/muleiwu/gohttpsig"
)

func main() {
    // Create credential store
    store := gohttpsig.NewInMemoryCredentialStore()
    store.AddCredentials(&gohttpsig.Credentials{
        AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
        SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    })

    // Create verifier
    verifier := gohttpsig.NewVerifier(store)

    // Use in HTTP handler
    http.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
        result, err := verifier.Verify(context.Background(), r)
        if err != nil || !result.Valid {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // Request is authenticated
        w.Write([]byte("Hello, " + result.AccessKeyID))
    })

    http.ListenAndServe(":8080", nil)
}
```

## Usage Guide

### Signing Options

The `Signer` supports various configuration options:

```go
signer := gohttpsig.NewSigner(
    provider,
    gohttpsig.WithUnsignedPayload(),                    // Don't sign payload
    gohttpsig.WithDisableURIPathEscaping(),             // For S3-compatible services
    gohttpsig.WithAdditionalSignedHeaders("X-Custom"),  // Include custom headers
)
```

### Presigned URLs

Generate time-limited URLs that can be used without credentials:

```go
req, _ := http.NewRequest("GET", "https://api.example.com/resource", nil)
presignedURL, err := signer.PresignRequest(
    context.Background(),
    req,
    "myservice",
    "us-east-1",
    15*time.Minute, // Expiration time
)

// Share presignedURL with clients
```

### Verification Options

Configure the `Verifier` with custom options:

```go
verifier := gohttpsig.NewVerifier(
    store,
    gohttpsig.WithMaxTimestampDrift(5*time.Minute),  // Allow 5 min clock drift
    gohttpsig.WithAllowUnsignedPayload(),            // Accept unsigned payloads
    gohttpsig.WithRequireSecurityToken(),            // Require session tokens
)
```

### Custom Credential Providers

Implement the `CredentialsProvider` interface for custom credential sources:

```go
type CredentialsProvider interface {
    Retrieve(ctx context.Context) (*Credentials, error)
}

// Example: Environment variable provider
type EnvCredentialsProvider struct{}

func (p *EnvCredentialsProvider) Retrieve(ctx context.Context) (*gohttpsig.Credentials, error) {
    return &gohttpsig.Credentials{
        AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
        SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
        SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
    }, nil
}
```

### Custom Credential Stores

Implement the `CredentialStore` interface for server-side credential lookup:

```go
type CredentialStore interface {
    GetCredentials(ctx context.Context, accessKeyID string) (*Credentials, error)
}

// Example: Database-backed store
type DatabaseCredentialStore struct {
    db *sql.DB
}

func (s *DatabaseCredentialStore) GetCredentials(ctx context.Context, accessKeyID string) (*gohttpsig.Credentials, error) {
    // Query database for credentials
    var creds gohttpsig.Credentials
    err := s.db.QueryRowContext(ctx,
        "SELECT access_key_id, secret_access_key FROM credentials WHERE access_key_id = $1",
        accessKeyID,
    ).Scan(&creds.AccessKeyID, &creds.SecretAccessKey)

    if err == sql.ErrNoRows {
        return nil, gohttpsig.ErrCredentialNotFound
    }
    return &creds, err
}
```

### Middleware Pattern

Create reusable authentication middleware:

```go
func AuthMiddleware(verifier *gohttpsig.Verifier) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            result, err := verifier.Verify(r.Context(), r)
            if err != nil || !result.Valid {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }

            // Add user info to context
            ctx := context.WithValue(r.Context(), "user", result.AccessKeyID)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

// Usage
mux.Handle("/api/", AuthMiddleware(verifier)(apiHandler))
```

## AWS Signature Version 4 Compliance

This library implements the complete AWS Signature Version 4 specification:

- ✅ RFC 3986 URI encoding with correct unreserved character set: `A-Z a-z 0-9 - _ . ~`
- ✅ Canonical request construction (method, URI, query, headers, payload)
- ✅ String to sign format (algorithm, timestamp, credential scope, hashed canonical request)
- ✅ 4-step HMAC-SHA256 signing key derivation
- ✅ Authorization header format: `AWS4-HMAC-SHA256 Credential=..., SignedHeaders=..., Signature=...`
- ✅ Required headers: `host`, `x-amz-date`, `x-amz-content-sha256`
- ✅ Header canonicalization (lowercase, trim, sort)
- ✅ Query string encoding (sorted, double-encoded values)
- ✅ ISO8601 timestamp format in UTC
- ✅ Constant-time signature comparison for security

## Examples

See the [examples/](examples/) directory for complete working examples:

- [**Client Example**](examples/client/main.go) - Sign and send HTTP requests
- [**Server Example**](examples/server/main.go) - Verify incoming requests with middleware
- [**Secure Storage Example**](examples/secure-storage/) - **⚠️ IMPORTANT**: How to securely store SecretAccessKey with AES-256-GCM encryption

### Running the Examples

Terminal 1 - Start the server:
```bash
cd examples/server
go run main.go
```

Terminal 2 - Run the client:
```bash
cd examples/client
go run main.go
```

## API Reference

### Core Types

```go
// Credentials represents AWS-style credentials
type Credentials struct {
    AccessKeyID     string
    SecretAccessKey string
    SessionToken    string  // Optional
}

// Signer signs HTTP requests
type Signer struct { /* ... */ }

// Verifier verifies HTTP request signatures
type Verifier struct { /* ... */ }

// VerificationResult contains verification details
type VerificationResult struct {
    Valid         bool
    AccessKeyID   string
    SignedHeaders []string
    RequestTime   time.Time
    Service       string
    Region        string
    Error         error
}
```

### Key Functions

```go
// Create a new signer
func NewSigner(creds CredentialsProvider, opts ...SignerOption) *Signer

// Sign an HTTP request
func (s *Signer) Sign(ctx context.Context, req *http.Request, service, region string) (*SignedRequest, error)

// Create a presigned URL
func (s *Signer) PresignRequest(ctx, req, service, region string, expiresIn time.Duration) (*url.URL, error)

// Create a new verifier
func NewVerifier(store CredentialStore, opts ...VerifierOption) *Verifier

// Verify an HTTP request signature
func (v *Verifier) Verify(ctx context.Context, req *http.Request) (*VerificationResult, error)
```

## Performance

Signing and verification are highly optimized:

```
BenchmarkSignerSign-8              20000    50000 ns/op    8192 B/op    95 allocs/op
BenchmarkDeriveSigningKey-8      200000     7500 ns/op     512 B/op     5 allocs/op
BenchmarkComputeSignature-8      500000     3000 ns/op     256 B/op     3 allocs/op
```

Typical performance:
- **Signing**: ~50µs per request
- **Verification**: ~55µs per request

## Security Considerations

### General Security

- **Constant-time comparison**: Signature verification uses `subtle.ConstantTimeCompare` to prevent timing attacks
- **Timestamp validation**: Requests outside the acceptable time drift window are rejected
- **HTTPS recommended**: While signatures protect against tampering, use HTTPS to prevent eavesdropping
- **Credential rotation**: Regularly rotate access keys and secret keys
- **Session tokens**: Use temporary credentials with session tokens for enhanced security

### SecretAccessKey Storage - Critical Security Notice ⚠️

**Important**: The client and server **must use the identical SecretAccessKey** because AWS Signature V4 uses HMAC (symmetric encryption):

- **Client**: `SecretAccessKey → HMAC → Signature → Send`
- **Server**: `SecretAccessKey → HMAC → Recompute Signature → Compare`

#### ❌ DO NOT Hash SecretAccessKey

Unlike password authentication, you **cannot** store hashed SecretAccessKey:

```go
// ❌ WRONG - This will NOT work!
hashedSecret := sha256.Sum256([]byte(secretKey))
// Cannot recompute HMAC from hash
```

**Why?** HMAC requires the original key to compute signatures. Hashing is one-way and irreversible.

#### ✅ Secure Storage Solutions

**Option 1: Database Field Encryption (AES-256-GCM)**

```go
package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "io"
)

type EncryptedCredentialStore struct {
    db            *sql.DB
    encryptionKey []byte // 32-byte AES-256 key from secure KMS
}

func (s *EncryptedCredentialStore) encryptSecret(plaintext string) (string, error) {
    block, err := aes.NewCipher(s.encryptionKey)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }

    ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (s *EncryptedCredentialStore) decryptSecret(encrypted string) (string, error) {
    data, err := base64.StdEncoding.DecodeString(encrypted)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(s.encryptionKey)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonceSize := gcm.NonceSize()
    nonce, ciphertext := data[:nonceSize], data[nonceSize:]

    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }

    return string(plaintext), nil
}

func (s *EncryptedCredentialStore) GetCredentials(ctx context.Context, accessKeyID string) (*gohttpsig.Credentials, error) {
    var encryptedSecret string
    err := s.db.QueryRowContext(ctx,
        "SELECT access_key_id, encrypted_secret_key FROM credentials WHERE access_key_id = $1",
        accessKeyID,
    ).Scan(&accessKeyID, &encryptedSecret)

    if err != nil {
        return nil, err
    }

    // Decrypt the secret key
    secretKey, err := s.decryptSecret(encryptedSecret)
    if err != nil {
        return nil, err
    }

    return &gohttpsig.Credentials{
        AccessKeyID:     accessKeyID,
        SecretAccessKey: secretKey,
    }, nil
}
```

**Option 2: Cloud KMS (AWS KMS, GCP KMS, Azure Key Vault)**

```go
type KMSCredentialStore struct {
    db        *sql.DB
    kmsClient *kms.KeyManagementClient
    keyName   string
}

func (s *KMSCredentialStore) GetCredentials(ctx context.Context, accessKeyID string) (*gohttpsig.Credentials, error) {
    var encryptedSecret []byte
    err := s.db.QueryRowContext(ctx,
        "SELECT access_key_id, kms_encrypted_secret FROM credentials WHERE access_key_id = $1",
        accessKeyID,
    ).Scan(&accessKeyID, &encryptedSecret)

    if err != nil {
        return nil, err
    }

    // Decrypt using KMS
    plaintext, err := s.kmsClient.Decrypt(ctx, &kms.DecryptRequest{
        KeyName:    s.keyName,
        Ciphertext: encryptedSecret,
    })

    return &gohttpsig.Credentials{
        AccessKeyID:     accessKeyID,
        SecretAccessKey: string(plaintext),
    }, nil
}
```

**Option 3: Environment Variables + Encrypted Config**

```go
// For development/testing environments
type EnvCredentialStore struct {
    credentials map[string]*gohttpsig.Credentials
}

func LoadFromEncryptedConfig(configPath, masterKey string) (*EnvCredentialStore, error) {
    // 1. Read encrypted configuration file
    // 2. Decrypt using master key
    // 3. Load into memory
    encryptedData, err := os.ReadFile(configPath)
    // ... decrypt and parse
}
```

#### Recommended Database Schema

```sql
CREATE TABLE api_credentials (
    id SERIAL PRIMARY KEY,
    access_key_id VARCHAR(128) UNIQUE NOT NULL,
    encrypted_secret_key TEXT NOT NULL,  -- AES-256-GCM encrypted
    encryption_key_version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_rotated_at TIMESTAMP,
    last_used_at TIMESTAMP,
    is_active BOOLEAN DEFAULT true,
    metadata JSONB,

    INDEX idx_access_key (access_key_id),
    INDEX idx_active (is_active)
);

-- Audit log for security monitoring
CREATE TABLE credential_audit_log (
    id SERIAL PRIMARY KEY,
    access_key_id VARCHAR(128),
    action VARCHAR(50),  -- 'created', 'rotated', 'revoked', 'accessed', 'failed'
    ip_address INET,
    user_agent TEXT,
    result VARCHAR(20),  -- 'success', 'failure'
    timestamp TIMESTAMP DEFAULT NOW(),

    INDEX idx_access_key_time (access_key_id, timestamp),
    INDEX idx_timestamp (timestamp)
);
```

#### Best Practices

**1. Use Temporary Credentials (Recommended)**

```go
type TemporaryCredentials struct {
    AccessKeyID     string
    SecretAccessKey string
    SessionToken    string
    Expiration      time.Time
}

func (s *CredentialStore) IssueTemporaryCredentials(userID string, duration time.Duration) (*TemporaryCredentials, error) {
    creds := &TemporaryCredentials{
        AccessKeyID:     generateAccessKeyID(),
        SecretAccessKey: generateSecureSecret(),
        SessionToken:    generateSessionToken(),
        Expiration:      time.Now().Add(duration),
    }

    // Store with expiration
    s.storeTemporary(creds)
    return creds, nil
}
```

**2. Implement Key Rotation**

```go
func (s *CredentialStore) RotateCredentials(ctx context.Context, accessKeyID string) error {
    newSecret := generateSecureSecret()
    encryptedSecret, _ := s.encrypt(newSecret)

    // Keep old key for grace period (e.g., 24 hours)
    _, err := s.db.ExecContext(ctx, `
        UPDATE credentials
        SET encrypted_secret_key = $1,
            old_encrypted_secret_key = encrypted_secret_key,
            last_rotated_at = NOW(),
            rotation_grace_period_until = NOW() + INTERVAL '24 hours'
        WHERE access_key_id = $2
    `, encryptedSecret, accessKeyID)

    return err
}
```

**3. Audit Logging**

```go
func (s *CredentialStore) GetCredentials(ctx context.Context, accessKeyID string) (*gohttpsig.Credentials, error) {
    // Always log access attempts
    defer func() {
        s.logAccess(ctx, accessKeyID, "accessed")
    }()

    // Check revocation status
    if s.isRevoked(ctx, accessKeyID) {
        s.logAccess(ctx, accessKeyID, "revoked_access_attempt")
        return nil, ErrCredentialRevoked
    }

    // Update last used timestamp
    defer s.updateLastUsed(ctx, accessKeyID)

    // ... fetch and decrypt credentials
}
```

**4. Rate Limiting & Anomaly Detection**

```go
func (s *CredentialStore) checkAnomalies(ctx context.Context, accessKeyID string) error {
    // Check for suspicious patterns
    count, err := s.getRecentFailureCount(ctx, accessKeyID, time.Hour)
    if err != nil {
        return err
    }

    if count > 10 {
        // Automatically revoke or require additional verification
        s.flagForReview(ctx, accessKeyID, "high_failure_rate")
        return ErrSuspiciousActivity
    }

    return nil
}
```

#### Security Checklist

- ✅ **Never store plaintext SecretAccessKey in database**
- ✅ **Use AES-256-GCM or cloud KMS for encryption**
- ✅ **Store encryption keys separately (e.g., environment variables, KMS)**
- ✅ **Implement key rotation every 90 days**
- ✅ **Use temporary credentials with expiration when possible**
- ✅ **Log all credential access attempts**
- ✅ **Monitor for anomalous usage patterns**
- ✅ **Implement automatic revocation on suspicious activity**
- ✅ **Use HTTPS for all API communications**
- ✅ **Regularly audit credential usage logs**

## Testing

Run the test suite:

```bash
# Run all tests
go test -v ./...

# Run tests with coverage
go test -cover ./...

# Run benchmarks
go test -bench=. ./...
```

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## References

- [AWS Signature Version 4 Documentation](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
- [RFC 3986 - URI Generic Syntax](https://tools.ietf.org/html/rfc3986)
- [AWS SigV4 Test Suite](https://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html)

## Acknowledgments

This library implements the AWS Signature Version 4 specification as documented by Amazon Web Services. It is designed to be compatible with AWS services and can also be used for custom HTTP API authentication.
