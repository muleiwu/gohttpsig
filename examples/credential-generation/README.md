# Credential Generation Guide

This example demonstrates how to securely generate AccessKeyID and SecretAccessKey pairs for AWS Signature V4 authentication.

## Requirements

### AccessKeyID Requirements

| Requirement | Specification |
|------------|---------------|
| **Length** | Exactly 20 characters |
| **Character Set** | Uppercase letters (A-Z) and digits (2-9) |
| **Prefix** | 4-character type identifier (e.g., AKIA, ASIA, AKSA) |
| **Uniqueness** | Must be unique across the system |
| **Visibility** | Public - can appear in logs and URLs |
| **Avoid Confusion** | Exclude 0, O, 1, I, L to prevent confusion |

**Format:**
```
AKIA + 16 random characters = 20 characters total
└─┬─┘   └────────┬────────┘
Prefix    Random Part

Examples:
- AKIAIOSFODNN7EXAMPLE  (Permanent credentials)
- ASIAIOSFODNN7EXAMPLE  (Temporary credentials)
- AKSAIOSFODNN7EXAMPLE  (Service credentials)
```

### SecretAccessKey Requirements

| Requirement | Specification |
|------------|---------------|
| **Length** | Minimum 32 characters, recommended 40 characters |
| **Character Set** | Mixed: uppercase, lowercase, digits, special characters (+/) |
| **Entropy** | Must use cryptographically secure random generator (`crypto/rand`) |
| **Diversity** | At least 3 different character types |
| **Uniqueness** | Must be unique across the system |
| **Visibility** | **PRIVATE** - never log, expose, or transmit unencrypted |

**Format:**
```
40 random characters from Base64 character set

Example:
wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
└──────────┬────────────────────────────────┘
    High-entropy random string
```

## Running the Example

```bash
cd examples/credential-generation
go run main.go
```

## Code Examples

### Basic Generation

```go
// Generate permanent credentials
creds, err := gohttpsig.GenerateCredentials()
if err != nil {
    log.Fatal(err)
}

fmt.Printf("AccessKeyID: %s\n", creds.AccessKeyID)
fmt.Printf("SecretAccessKey: %s\n", creds.SecretAccessKey)
```

### Generate with Specific Prefix

```go
// Permanent credentials (AKIA)
permanent, _ := gohttpsig.GenerateCredentialsWithPrefix(gohttpsig.PrefixPermanent)

// Temporary credentials (ASIA)
temporary, _ := gohttpsig.GenerateCredentialsWithPrefix(gohttpsig.PrefixTemporary)

// Service credentials (AKSA)
service, _ := gohttpsig.GenerateCredentialsWithPrefix(gohttpsig.PrefixService)
```

### Generate with Session Token

```go
// For temporary credentials
creds, _ := gohttpsig.GenerateCredentialsWithPrefix(gohttpsig.PrefixTemporary)
sessionToken, _ := gohttpsig.GenerateSessionToken()
creds.SessionToken = sessionToken

// Now you have temporary credentials with expiration
```

### Validate Credentials

```go
// Validate AccessKeyID format
err := gohttpsig.ValidateAccessKeyID(creds.AccessKeyID)
if err != nil {
    log.Printf("Invalid AccessKeyID: %v", err)
}

// Validate SecretAccessKey strength
err = gohttpsig.ValidateSecretAccessKey(creds.SecretAccessKey)
if err != nil {
    log.Printf("Weak SecretAccessKey: %v", err)
}
```

### Evaluate Credential Strength

```go
strength := gohttpsig.EvaluateCredentialStrength(creds)

fmt.Printf("Strength Score: %d/100\n", strength.Score)
fmt.Printf("Is Strong: %v\n", strength.IsStrong)

if len(strength.Issues) > 0 {
    fmt.Println("Issues found:")
    for _, issue := range strength.Issues {
        fmt.Printf("  - %s\n", issue)
    }
}
```

## Security Best Practices

### ✅ DO

1. **Use Cryptographic Random Generator**
   ```go
   // ✅ CORRECT
   import "crypto/rand"
   rand.Read(bytes)
   ```

2. **Store SecretAccessKey Encrypted**
   ```go
   // ✅ CORRECT
   encrypted := aesGcmEncrypt(secretKey, encryptionKey)
   db.Save(accessKeyID, encrypted)
   ```

3. **Display Secret Only Once**
   ```go
   // ✅ CORRECT
   creds, _ := GenerateCredentials()
   fmt.Printf("⚠️  Save this SecretAccessKey now - it won't be shown again!\n")
   fmt.Printf("SecretAccessKey: %s\n", creds.SecretAccessKey)
   // Then encrypt and store
   ```

4. **Implement Rotation**
   ```go
   // ✅ CORRECT
   if time.Since(creds.CreatedAt) > 90*24*time.Hour {
       newCreds := GenerateCredentials()
       RotateCredentials(oldAccessKeyID, newCreds)
   }
   ```

5. **Use Temporary Credentials**
   ```go
   // ✅ CORRECT - expires automatically
   tempCreds := IssueTemporaryCredentials(userID, 1*time.Hour)
   ```

### ❌ DON'T

1. **Don't Use Math/Rand**
   ```go
   // ❌ WRONG - not cryptographically secure
   import "math/rand"
   rand.Seed(time.Now().Unix())
   ```

2. **Don't Use Predictable Values**
   ```go
   // ❌ WRONG - predictable
   accessKeyID := "AKIA" + timestamp
   secretKey := username + timestamp
   ```

3. **Don't Store Plaintext**
   ```go
   // ❌ WRONG - never store plaintext
   db.Exec("INSERT INTO creds VALUES (?, ?)", accessKeyID, secretKey)
   ```

4. **Don't Hash SecretAccessKey**
   ```go
   // ❌ WRONG - cannot use hash for HMAC
   hashed := sha256.Sum256([]byte(secretKey))
   db.Save(accessKeyID, hashed)
   ```

5. **Don't Log Secrets**
   ```go
   // ❌ WRONG - secrets in logs
   log.Printf("Generated secret: %s", secretKey)

   // ✅ CORRECT - safe logging
   log.Printf("Generated credentials for: %s", accessKeyID)
   ```

6. **Don't Use Short Keys**
   ```go
   // ❌ WRONG - too short, low entropy
   secretKey := "password123"

   // ✅ CORRECT - 40+ chars, high entropy
   secretKey := GenerateSecretAccessKey()
   ```

## Credential Types

### 1. Permanent Credentials (AKIA)

- **Use Case**: Long-term IAM user credentials
- **Prefix**: `AKIA`
- **Expiration**: Never (manual rotation required)
- **Best For**: Service accounts, CI/CD systems
- **Security**: Rotate every 90 days

```go
creds, _ := GenerateCredentialsWithPrefix(gohttpsig.PrefixPermanent)
// AKIAIOSFODNN7EXAMPLE
```

### 2. Temporary Credentials (ASIA)

- **Use Case**: Short-term session credentials
- **Prefix**: `ASIA`
- **Expiration**: 15 minutes to 12 hours
- **Best For**: User sessions, temporary access
- **Security**: Automatically expires

```go
creds, _ := GenerateCredentialsWithPrefix(gohttpsig.PrefixTemporary)
sessionToken, _ := GenerateSessionToken()
creds.SessionToken = sessionToken
// ASIAIOSFODNN7EXAMPLE
```

### 3. Service Credentials (AKSA)

- **Use Case**: Service-to-service authentication
- **Prefix**: `AKSA`
- **Expiration**: Custom policy
- **Best For**: Microservices, internal APIs
- **Security**: Scoped permissions

```go
creds, _ := GenerateCredentialsWithPrefix(gohttpsig.PrefixService)
// AKSAIOSFODNN7EXAMPLE
```

## Complete Workflow Example

```go
package main

import (
    "fmt"
    "log"
    "time"
    "github.com/muleiwu/gohttpsig"
)

func IssueCredentialsToUser(userID string) error {
    // 1. Generate credentials
    creds, err := gohttpsig.GenerateCredentials()
    if err != nil {
        return err
    }

    // 2. Validate strength
    strength := gohttpsig.EvaluateCredentialStrength(creds)
    if !strength.IsStrong {
        return fmt.Errorf("generated weak credentials: %v", strength.Issues)
    }

    // 3. Encrypt secret key
    encryptedSecret := encryptWithAES256GCM(
        creds.SecretAccessKey,
        getEncryptionKey(),
    )

    // 4. Store in database
    err = db.Exec(`
        INSERT INTO api_credentials
        (user_id, access_key_id, encrypted_secret_key, created_at)
        VALUES ($1, $2, $3, $4)
    `, userID, creds.AccessKeyID, encryptedSecret, time.Now())
    if err != nil {
        return err
    }

    // 5. Display to user (ONLY ONCE)
    fmt.Println("=== Your New API Credentials ===")
    fmt.Printf("AccessKeyID:     %s\n", creds.AccessKeyID)
    fmt.Printf("SecretAccessKey: %s\n", creds.SecretAccessKey)
    fmt.Println()
    fmt.Println("⚠️  IMPORTANT: Save the SecretAccessKey now!")
    fmt.Println("   It will not be shown again for security reasons.")

    // 6. Log audit event (WITHOUT secret)
    auditLog.Record("credential_issued", map[string]interface{}{
        "user_id":       userID,
        "access_key_id": creds.AccessKeyID,
        "timestamp":     time.Now(),
    })

    return nil
}
```

## Testing

Run the test suite:

```bash
# Run all credential generation tests
go test -v -run TestGenerate

# Run with coverage
go test -cover -run TestGenerate

# Run benchmarks
go test -bench=BenchmarkGenerate
```

## Performance

Credential generation is highly optimized:

```
BenchmarkGenerateAccessKeyID-8        500000    3000 ns/op
BenchmarkGenerateSecretAccessKey-8    200000    5000 ns/op
BenchmarkGenerateCredentials-8        100000    8000 ns/op
```

- AccessKeyID: ~3µs per generation
- SecretAccessKey: ~5µs per generation
- Full credentials: ~8µs per generation

## Security Checklist

- [ ] Use `crypto/rand` (not `math/rand`)
- [ ] AccessKeyID is exactly 20 characters
- [ ] SecretAccessKey is at least 40 characters
- [ ] SecretAccessKey has high entropy
- [ ] Store SecretAccessKey encrypted (AES-256-GCM or KMS)
- [ ] Never log SecretAccessKey
- [ ] Display SecretAccessKey only once to user
- [ ] Implement 90-day rotation schedule
- [ ] Use temporary credentials when possible
- [ ] Enable audit logging for credential access
- [ ] Monitor for anomalous usage patterns
- [ ] Have credential revocation process

## Further Reading

- [AWS Access Keys Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html)
- [NIST Guidelines on Random Number Generation](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
- [Cryptographically Secure Randomness](https://pkg.go.dev/crypto/rand)
