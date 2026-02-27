package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"time"

	"github.com/muleiwu/gohttpsig"
)

// EncryptedCredentialStore implements a secure credential store with AES-256-GCM encryption
// This is the RECOMMENDED way to store SecretAccessKey in production
type EncryptedCredentialStore struct {
	db            *sql.DB
	encryptionKey []byte // 32-byte AES-256 key - MUST be stored securely (env var, KMS, etc.)
}

// NewEncryptedCredentialStore creates a new encrypted credential store
// The encryptionKey MUST be 32 bytes for AES-256
func NewEncryptedCredentialStore(db *sql.DB, encryptionKey []byte) (*EncryptedCredentialStore, error) {
	if len(encryptionKey) != 32 {
		return nil, errors.New("encryption key must be 32 bytes for AES-256")
	}

	return &EncryptedCredentialStore{
		db:            db,
		encryptionKey: encryptionKey,
	}, nil
}

// encryptSecret encrypts a secret key using AES-256-GCM
func (s *EncryptedCredentialStore) encryptSecret(plaintext string) (string, error) {
	// Create cipher block
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return "", err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	// Encode to base64 for storage
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptSecret decrypts a secret key using AES-256-GCM
func (s *EncryptedCredentialStore) decryptSecret(encrypted string) (string, error) {
	// Decode from base64
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	// Create cipher block
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return "", err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Extract nonce and ciphertext
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// Decrypt the data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// AddCredentials adds new credentials with encryption
func (s *EncryptedCredentialStore) AddCredentials(ctx context.Context, creds *gohttpsig.Credentials) error {
	if err := creds.Validate(); err != nil {
		return err
	}

	// Encrypt the secret key
	encryptedSecret, err := s.encryptSecret(creds.SecretAccessKey)
	if err != nil {
		return err
	}

	// Encrypt session token if present
	var encryptedToken sql.NullString
	if creds.SessionToken != "" {
		encrypted, err := s.encryptSecret(creds.SessionToken)
		if err != nil {
			return err
		}
		encryptedToken = sql.NullString{String: encrypted, Valid: true}
	}

	// Insert into database
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO api_credentials (access_key_id, encrypted_secret_key, encrypted_session_token, created_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (access_key_id) DO UPDATE
		SET encrypted_secret_key = EXCLUDED.encrypted_secret_key,
		    encrypted_session_token = EXCLUDED.encrypted_session_token,
		    updated_at = NOW()
	`, creds.AccessKeyID, encryptedSecret, encryptedToken, time.Now())

	if err != nil {
		return err
	}

	// Log the credential creation
	s.logAudit(ctx, creds.AccessKeyID, "created", "success")

	return nil
}

// GetCredentials retrieves and decrypts credentials (implements gohttpsig.CredentialStore)
func (s *EncryptedCredentialStore) GetCredentials(ctx context.Context, accessKeyID string) (*gohttpsig.Credentials, error) {
	// Always log access attempts
	defer func() {
		s.logAudit(ctx, accessKeyID, "accessed", "success")
	}()

	// Check if credentials are active
	var encryptedSecret string
	var encryptedToken sql.NullString
	var isActive bool
	var lastUsedAt sql.NullTime

	err := s.db.QueryRowContext(ctx, `
		SELECT encrypted_secret_key, encrypted_session_token, is_active, last_used_at
		FROM api_credentials
		WHERE access_key_id = $1
	`, accessKeyID).Scan(&encryptedSecret, &encryptedToken, &isActive, &lastUsedAt)

	if err == sql.ErrNoRows {
		s.logAudit(ctx, accessKeyID, "accessed", "not_found")
		return nil, gohttpsig.ErrCredentialNotFound
	}
	if err != nil {
		s.logAudit(ctx, accessKeyID, "accessed", "error")
		return nil, err
	}

	// Check if credentials are revoked
	if !isActive {
		s.logAudit(ctx, accessKeyID, "revoked_access_attempt", "failure")
		return nil, errors.New("credentials have been revoked")
	}

	// Decrypt the secret key
	secretKey, err := s.decryptSecret(encryptedSecret)
	if err != nil {
		s.logAudit(ctx, accessKeyID, "decryption_failed", "error")
		return nil, err
	}

	// Decrypt session token if present
	var sessionToken string
	if encryptedToken.Valid {
		sessionToken, err = s.decryptSecret(encryptedToken.String)
		if err != nil {
			s.logAudit(ctx, accessKeyID, "decryption_failed", "error")
			return nil, err
		}
	}

	// Update last used timestamp
	go s.updateLastUsed(context.Background(), accessKeyID)

	return &gohttpsig.Credentials{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretKey,
		SessionToken:    sessionToken,
	}, nil
}

// RotateCredentials rotates the secret key while keeping the old one for a grace period
func (s *EncryptedCredentialStore) RotateCredentials(ctx context.Context, accessKeyID string, newSecretKey string) error {
	// Encrypt the new secret key
	encryptedNew, err := s.encryptSecret(newSecretKey)
	if err != nil {
		return err
	}

	// Move current key to old_encrypted_secret_key, set new key, and set grace period
	_, err = s.db.ExecContext(ctx, `
		UPDATE api_credentials
		SET encrypted_secret_key = $1,
		    old_encrypted_secret_key = encrypted_secret_key,
		    last_rotated_at = NOW(),
		    rotation_grace_period_until = NOW() + INTERVAL '24 hours',
		    updated_at = NOW()
		WHERE access_key_id = $2
	`, encryptedNew, accessKeyID)

	if err != nil {
		return err
	}

	// Log the rotation
	s.logAudit(ctx, accessKeyID, "rotated", "success")

	return nil
}

// RevokeCredentials marks credentials as inactive
func (s *EncryptedCredentialStore) RevokeCredentials(ctx context.Context, accessKeyID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE api_credentials
		SET is_active = false,
		    updated_at = NOW()
		WHERE access_key_id = $1
	`, accessKeyID)

	if err != nil {
		return err
	}

	// Log the revocation
	s.logAudit(ctx, accessKeyID, "revoked", "success")

	return nil
}

// updateLastUsed updates the last_used_at timestamp
func (s *EncryptedCredentialStore) updateLastUsed(ctx context.Context, accessKeyID string) {
	_, err := s.db.ExecContext(ctx, `
		UPDATE api_credentials
		SET last_used_at = NOW()
		WHERE access_key_id = $1
	`, accessKeyID)

	if err != nil {
		log.Printf("Failed to update last_used_at for %s: %v", accessKeyID, err)
	}
}

// logAudit logs credential access to the audit log
func (s *EncryptedCredentialStore) logAudit(ctx context.Context, accessKeyID, action, result string) {
	// Extract IP address from context if available
	ipAddress := "unknown"
	userAgent := "unknown"

	// In a real application, you would extract these from the HTTP request context
	// if ip, ok := ctx.Value("ip_address").(string); ok {
	//     ipAddress = ip
	// }

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO credential_audit_log (access_key_id, action, ip_address, user_agent, result, timestamp)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, accessKeyID, action, ipAddress, userAgent, result, time.Now())

	if err != nil {
		log.Printf("Failed to log audit entry: %v", err)
	}
}

// CreateTables creates the necessary database tables
func CreateTables(db *sql.DB) error {
	schema := `
		CREATE TABLE IF NOT EXISTS api_credentials (
			id SERIAL PRIMARY KEY,
			access_key_id VARCHAR(128) UNIQUE NOT NULL,
			encrypted_secret_key TEXT NOT NULL,
			encrypted_session_token TEXT,
			old_encrypted_secret_key TEXT,
			encryption_key_version INT NOT NULL DEFAULT 1,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			last_rotated_at TIMESTAMP,
			last_used_at TIMESTAMP,
			rotation_grace_period_until TIMESTAMP,
			is_active BOOLEAN DEFAULT true,
			metadata JSONB
		);

		CREATE INDEX IF NOT EXISTS idx_access_key ON api_credentials(access_key_id);
		CREATE INDEX IF NOT EXISTS idx_active ON api_credentials(is_active);

		CREATE TABLE IF NOT EXISTS credential_audit_log (
			id SERIAL PRIMARY KEY,
			access_key_id VARCHAR(128),
			action VARCHAR(50),
			ip_address INET,
			user_agent TEXT,
			result VARCHAR(20),
			timestamp TIMESTAMP DEFAULT NOW()
		);

		CREATE INDEX IF NOT EXISTS idx_audit_access_key_time ON credential_audit_log(access_key_id, timestamp);
		CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON credential_audit_log(timestamp);
	`

	_, err := db.Exec(schema)
	return err
}
