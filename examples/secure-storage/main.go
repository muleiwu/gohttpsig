package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"

	_ "github.com/lib/pq" // PostgreSQL driver (for demonstration)
	"github.com/muleiwu/gohttpsig"
)

func main() {
	fmt.Println("=== Secure Credential Storage Example ===")
	fmt.Println()

	// Example 1: Generate a secure encryption key
	fmt.Println("1. Generating a secure 32-byte encryption key...")
	encryptionKey := generateEncryptionKey()
	fmt.Printf("   Encryption key (hex): %s\n", hex.EncodeToString(encryptionKey))
	fmt.Println("   ⚠️  In production, store this key securely (environment variable, KMS, etc.)")
	fmt.Println()

	// Example 2: In-memory demonstration (no database required)
	fmt.Println("2. Demonstrating encryption/decryption...")
	demonstrateEncryption(encryptionKey)
	fmt.Println()

	// Example 3: Full workflow with mock database
	fmt.Println("3. Full workflow demonstration (without actual database):")
	demonstrateFullWorkflow()
	fmt.Println()

	// Example 4: How to use with real database (commented out)
	fmt.Println("4. To use with a real database:")
	fmt.Println("   - Set DATABASE_URL environment variable")
	fmt.Println("   - Set ENCRYPTION_KEY environment variable")
	fmt.Println("   - Uncomment the database example in main.go")
	fmt.Println()

	// Uncomment to run with real database:
	// runWithDatabase()
}

// generateEncryptionKey generates a cryptographically secure 32-byte key
func generateEncryptionKey() []byte {
	key := make([]byte, 32) // 32 bytes = 256 bits for AES-256
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("Failed to generate encryption key: %v", err)
	}
	return key
}

// demonstrateEncryption shows how credentials are encrypted and decrypted
func demonstrateEncryption(encryptionKey []byte) {
	// Create a mock database (nil is ok for demonstration)
	store, err := NewEncryptedCredentialStore(nil, encryptionKey)
	if err != nil {
		log.Fatalf("Failed to create store: %v", err)
	}

	// Original credentials
	originalSecret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	fmt.Printf("   Original secret: %s\n", originalSecret)

	// Encrypt
	encrypted, err := store.encryptSecret(originalSecret)
	if err != nil {
		log.Fatalf("Failed to encrypt: %v", err)
	}
	fmt.Printf("   Encrypted (base64): %s...\n", encrypted[:40])

	// Decrypt
	decrypted, err := store.decryptSecret(encrypted)
	if err != nil {
		log.Fatalf("Failed to decrypt: %v", err)
	}
	fmt.Printf("   Decrypted secret: %s\n", decrypted)

	// Verify
	if originalSecret == decrypted {
		fmt.Println("   ✅ Encryption/decryption successful!")
	} else {
		fmt.Println("   ❌ Encryption/decryption failed!")
	}
}

// demonstrateFullWorkflow shows the complete workflow
func demonstrateFullWorkflow() {
	fmt.Println("   a. Client signs request with credentials")
	fmt.Println("   b. Server retrieves encrypted credentials from database")
	fmt.Println("   c. Server decrypts credentials")
	fmt.Println("   d. Server verifies signature using decrypted credentials")
	fmt.Println("   e. Audit log records access")
	fmt.Println()
	fmt.Println("   See examples/secure-storage/encrypted_store.go for implementation")
}

// runWithDatabase demonstrates using the encrypted store with a real database
// Uncomment the call in main() to use this
func runWithDatabase() {
	// Get database URL from environment
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "postgres://user:password@localhost/gohttpsig?sslmode=disable"
		log.Printf("DATABASE_URL not set, using default: %s", databaseURL)
	}

	// Get encryption key from environment
	encryptionKeyHex := os.Getenv("ENCRYPTION_KEY")
	if encryptionKeyHex == "" {
		log.Fatal("ENCRYPTION_KEY environment variable is required")
	}

	encryptionKey, err := hex.DecodeString(encryptionKeyHex)
	if err != nil || len(encryptionKey) != 32 {
		log.Fatal("ENCRYPTION_KEY must be a 64-character hex string (32 bytes)")
	}

	// Connect to database
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Create tables
	if err := CreateTables(db); err != nil {
		log.Fatalf("Failed to create tables: %v", err)
	}

	// Create encrypted credential store
	store, err := NewEncryptedCredentialStore(db, encryptionKey)
	if err != nil {
		log.Fatalf("Failed to create store: %v", err)
	}

	// Add credentials
	creds := &gohttpsig.Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	ctx := context.Background()
	if err := store.AddCredentials(ctx, creds); err != nil {
		log.Fatalf("Failed to add credentials: %v", err)
	}

	fmt.Println("✅ Credentials stored securely with encryption")

	// Create verifier
	verifier := gohttpsig.NewVerifier(store)

	// Create HTTP handler
	http.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		result, err := verifier.Verify(r.Context(), r)
		if err != nil || !result.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		fmt.Fprintf(w, "Authenticated as: %s", result.AccessKeyID)
	})

	// Start server
	addr := ":8080"
	log.Printf("Server starting on %s", addr)
	log.Printf("Credentials are encrypted in database with AES-256-GCM")
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
